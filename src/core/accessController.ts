import * as _ from 'lodash';
import * as nodeEval from 'node-eval';
import {
  Rule, Policy, PolicySet, Request, Response,
  Decision, Effect, Target, CombiningAlgorithm, AccessControlConfiguration,
  Attribute, ContextQuery, PolicySetRQ, PolicyRQ, RuleRQ, AccessControlOperation
} from './interfaces';
import { ResourceAdapter, GraphQLAdapter } from './resource_adapters';
import * as errors from './errors';
import { checkHierarchicalScope } from './hierarchicalScope';
import { Logger } from '@restorecommerce/chassis-srv';

export class AccessController {
  policySets: Map<string, PolicySet>;
  combiningAlgorithms: Map<string, any>;
  urns: Map<string, string>;
  resourceAdapter: ResourceAdapter;
  constructor(private logger: Logger, opts: AccessControlConfiguration) {
    this.policySets = new Map<string, PolicySet>();
    this.combiningAlgorithms = new Map<string, any>();

    logger.info('Parsing combining algorithms from access control configuration...');
    //  parsing URNs and mapping them to functions
    const combiningAlgorithms: CombiningAlgorithm[] = opts.combiningAlgorithms || [];
    for (let ca of combiningAlgorithms) {
      const urn = ca.urn;
      const method = ca.method;

      if (this[method]) {
        this.combiningAlgorithms.set(urn, this[method]);
      } else {
        logger.error('Unable to setup access controller: an invalid combining algorithm was found!');
        throw new errors.InvalidCombiningAlgorithm(urn);
      }
    }

    this.urns = new Map<string, string>();
    for (let urn in opts.urns || {}) {
      this.urns.set(urn, opts.urns[urn]);
    }
  }

  clearPolicies(): void {
    this.policySets.clear();
  }

  /**
   * Method invoked for access control logic.
   *
   * @param request
   */
  async isAllowed(request: Request): Promise<Response> {

    this.logger.silly('Received an access request');
    if (!request.target) {
      this.logger.silly('Access request had no target. Skipping request.');
      throw new errors.InvalidRequest('target');
    }

    const requestTarget = request.target;
    let effect: Effect;
    for (let [, value] of this.policySets) {
      const policySet: PolicySet = value;
      let policyEffects: Effect[] = [];

      if ((!!policySet.target && this.targetMatches(policySet.target, request.target))
        || !policySet.target) {

        for (let [, policyValue] of policySet.combinables) {
          const policy: Policy = policyValue;

          const ruleEffects: Effect[] = [];
          if ((!!policy.target && this.targetMatches(policy.target, request.target))
            || !policy.target) {

            const rules: Map<string, Rule> = policy.combinables;
            this.logger.verbose(`Checking policy ${policy.name}...`);
            // only apply a policy effect if there are no rules
            // combine rules otherwise
            if (rules.size == 0 && !!policy.effect) {
              policyEffects.push(policy.effect);
            }

            else {
              for (let [, rule] of policy.combinables) {
                // if rule has not target it should be always applied inside the policy scope
                let matches = !rule.target || this.targetMatches(rule.target, requestTarget);

                if (matches) {
                  this.logger.verbose(`Checking rule ${rule.name}...`);
                  if (matches && rule.target) {
                    matches = checkHierarchicalScope(rule.target, request, this.urns);
                  }

                  try {
                    if (matches && !_.isEmpty(rule.condition)) {
                      // context query is only checked when a rule exists
                      let context: any;
                      if (!_.isEmpty(rule.contextQuery) && this.resourceAdapter) {
                        context = await this.pullContextResources(rule.contextQuery, request);

                        if (_.isNil(context)) {
                          return {  // deny by default
                            decision: Decision.DENY,
                            obligation: ''
                          };
                        }
                      }

                      request.context = context || request.context;
                      matches = this.conditionMatches(rule.condition, request);
                    }
                  } catch (err) {
                    this.logger.error('Caught an exception while applying rule condition to request: ', err);
                    // this.logger.verbose(err.stack);
                    return {  // if an exception is caught deny by default
                      decision: Decision.DENY,
                      obligation: ''
                    };
                  }

                  if (matches) {
                    ruleEffects.push(rule.effect);
                  }
                }
              }

              if (ruleEffects.length > 0) {
                policyEffects.push(this.decide(policy.combiningAlgorithm, ruleEffects));
              }
            }
          }
        }

        if (policyEffects.length > 0) {
          effect = this.decide(policySet.combiningAlgorithm, policyEffects);
        }
      }
    }

    if (!effect) {
      this.logger.silly('Access response is INDETERMINATE');
      return {
        decision: Decision.INDETERMINATE,
        obligation: ''
      };
    }

    let decision: Decision;

    decision = Decision[effect] || Decision.INDETERMINATE;

    this.logger.silly('Access response is', decision);
    return {
      decision,
      obligation: ''
    };
  }

  whatIsAllowed(request: Request): PolicySetRQ[] {
    let policySets: PolicySetRQ[] = [];
    for (let [, value] of this.policySets) {
      let pSet: PolicySetRQ;
      if (_.isEmpty(value.target) || this.targetMatches(value.target, request.target)) {
        pSet = _.merge({}, { combining_algorithm: value.combiningAlgorithm }, _.pick(value, ['id', 'target', 'effect']));
        pSet.policies = [];

        for (let [, policy] of value.combinables) {
          let policyRQ: PolicyRQ;
          if (_.isEmpty(policy.target) || this.targetMatches(policy.target, request.target)) {
            policyRQ = _.merge({}, { combining_algorithm: policy.combiningAlgorithm }, _.pick(policy, ['id', 'target', 'effect']));
            policyRQ.rules = [];

            policyRQ.has_rules = (!!policy.combinables && policy.combinables.size > 0);

            for (let [, rule] of policy.combinables) {
              let ruleRQ: RuleRQ;
              if (_.isEmpty(rule.target) || this.targetMatches(rule.target, request.target, 'whatIsAllowed')) {
                ruleRQ = _.merge({}, { context_query: rule.contextQuery }, _.pick(rule, ['id', 'target', 'effect', 'condition']));
                policyRQ.rules.push(ruleRQ);
              }
            }
            if (!!policyRQ.effect || (!policyRQ.effect && !_.isEmpty(policyRQ.rules))) {
              pSet.policies.push(policyRQ);
            }
          }
        }
        if (!_.isEmpty(pSet.policies)) {
          policySets.push(pSet);
        }
      }
    }
    return policySets;
  }

  /**
 * Check if a request's target matches a rule, policy or policy set's target.
 * @param targetA
 * @param targetB
 */
  private targetMatches(ruleTarget: Target, requestTarget: Target, operation: AccessControlOperation = 'isAllowed'): boolean {
    const subjectMatches = (operation == 'whatIsAllowed' && _.isEmpty(requestTarget.subject))
      || this.attributesMatch(ruleTarget.subject, requestTarget.subject);

    const match = subjectMatches && this.attributesMatch(ruleTarget.action, requestTarget.action);
    if (!match) {
      return false;
    }
    switch (operation) {
      case 'whatIsAllowed':
        // only searching for entity types on the rule target
        // WhatIsAllowed is not designed to match resource instances
        const urn = this.urns.get('entity');
        for (let attribute of ruleTarget.resources) {
          if (attribute.id == urn) {
            let found = false;
            for (let reqAttribute of requestTarget.resources) {
              if (reqAttribute.id == urn && reqAttribute.value == attribute.value) {
                found = true;
                break;
              } else if (reqAttribute.id == urn) {
                // check for regex pattern
                const value = attribute.value;
                let pattern = value.substring(value.lastIndexOf(':') + 1);
                let regexValue = pattern.split('.')[0];
                const reExp = new RegExp(regexValue);
                if (reqAttribute.value.match(reExp)) {
                  found = true;
                  break;
                }
              }
            }

            if (!found) {
              return false;
            }
          }
        }
        return true;
      case 'isAllowed':
      default:
        return this.attributesMatch(ruleTarget.resources, requestTarget.resources);
    }
  }

  /**
 * Check if the attributes of a subject, action or resources from a rule, policy
 * or policy set match the attributes from a request.
 *
 * @param ruleAttributes
 * @param requestAttributes
 */
  private attributesMatch(ruleAttributes: Attribute[], requestAttributes: Attribute[]): boolean {

    for (let attribute of ruleAttributes) {
      const id = attribute.id;
      const value = attribute.value;
      const match = !!requestAttributes.find((requestAttribute) => {
        // return requestAttribute.id == id && requestAttribute.value == value;
        if (requestAttribute.id == id && requestAttribute.value == value) {
          return true;
        } else if (requestAttribute.id == id) {
          let pattern = value.substring(value.lastIndexOf(':') + 1);
          let regexValue = pattern.split('.')[0];
          const reExp = new RegExp(regexValue);
          if (requestAttribute.value.match(reExp)) {
            return true;
          }
        } else {
          return false;
        }
      });

      if (!match) {
        return false;
      }
    }

    return true;
  }

  /**
   * A list of rules or policies provides a list of Effects.
   * This method is invoked to evaluate the final effect
   * according to a combining algorithm
   * @param combiningAlgorithm
   * @param effects
   */
  private decide(combiningAlgorithm: string, effects: Effect[]): Effect {
    if (this.combiningAlgorithms.has(combiningAlgorithm)) {
      return this.combiningAlgorithms.get(combiningAlgorithm).apply(this, [effects]);
    }

    throw new errors.InvalidCombiningAlgorithm(combiningAlgorithm);
  }

  private conditionMatches(condition: string, request: Request): boolean {
    condition = condition.replace(/\\n/g, '\n');
    return nodeEval(condition, 'condition.js', request);
  }

  // Combining algorithms

  /**
  * Always DENY if DENY exists;
  * @param effects
  */
  protected denyOverrides(effects: Effect[]): Effect {
    return _.includes(effects, Effect.DENY) ? Effect.DENY : Effect.PERMIT;
  }

  /**
   * Always PERMIT if PERMIT exists;
   * @param effects
   */
  protected permitOverrides(effects: Effect[]): Effect {
    return _.includes(effects, Effect.PERMIT) ? Effect.PERMIT : Effect.DENY;
  }

  /**
   * Apply first effect which matches PERMIT or DENY.
   * Note that in a future implementation Effect may be extended to further values.
   * @param effects
   */
  protected firstApplicable(effects: Effect[]): Effect {
    return effects[0];
  }

  // in-memory resource handlers

  updatePolicySet(policySet: PolicySet): void {
    this.policySets.set(policySet.id, policySet);
  }

  removePolicySet(policySetID: string): void {
    this.policySets.delete(policySetID);
  }

  updatePolicy(policySetID: string, policy: Policy): void {
    const policySet: PolicySet = this.policySets.get(policySetID);
    if (!_.isNil(policySet)) {
      policySet.combinables.set(policy.id, policy);
    }
  }

  removePolicy(policySetID: string, policyID: string): void {
    const policySet: PolicySet = this.policySets.get(policySetID);
    if (!_.isNil(policySet)) {
      policySet.combinables.delete(policyID);
    }
  }

  updateRule(policySetID: string, policyID: string, rule: Rule): void {
    const policySet: PolicySet = this.policySets.get(policySetID);
    if (!_.isNil(policySet)) {
      const policy: Policy = policySet.combinables.get(policyID);
      if (!_.isNil(policy)) {
        policy.combinables.set(rule.id, rule);
      }
    }
  }

  removeRule(policySetID: string, policyID: string, ruleID: string): void {
    const policySet: PolicySet = this.policySets.get(policySetID);
    if (!_.isNil(policySet)) {
      const policy: Policy = policySet.combinables.get(policyID);
      if (!_.isNil(policy)) {
        policy.combinables.delete(ruleID);
      }
    }
  }

  /**
   * Creates an adapter within the supported resource adapters.
   * @param adapterConfig
   */
  createResourceAdapter(adapterConfig: any): void {

    if (!_.isNil(adapterConfig.graphql)) {
      const opts = adapterConfig.graphql;
      this.resourceAdapter = new GraphQLAdapter(opts.url, this.logger, opts.clientOpts);
    } else {
      throw new errors.UnsupportedResourceAdapter(adapterConfig);
    }
  }

  /**
   * Invokes adapter to pull necessary resources
   * and appends them to the request's context under the property `_queryResult`.
   * @param contextQuery A ContextQuery object.
   * @param context The request's context.
   */
  async pullContextResources(contextQuery: ContextQuery, request: Request): Promise<any> {
    const result = await this.resourceAdapter.query(contextQuery, request);

    return _.merge({}, context, {
      _queryResult: result
    });
  }
}
