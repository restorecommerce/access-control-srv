import * as _ from 'lodash';
import * as nodeEval from 'node-eval';
import {
  Rule, Policy, PolicySet, Request, Response,
  Decision, Effect, Target, CombiningAlgorithm, AccessControlConfiguration,
  Attribute, ContextQuery, PolicySetRQ, PolicyRQ, RuleRQ, AccessControlOperation, HierarchicalScope, EffectEvaluation
} from './interfaces';
import { ResourceAdapter, GraphQLAdapter } from './resource_adapters';
import * as errors from './errors';
import { checkHierarchicalScope } from './hierarchicalScope';
import { Logger } from 'winston';
import { RedisClient, createClient } from 'redis';
import { Topic } from '@restorecommerce/kafka-client';

export class AccessController {
  policySets: Map<string, PolicySet>;
  combiningAlgorithms: Map<string, any>;
  urns: Map<string, string>;
  resourceAdapter: ResourceAdapter;
  redisClient: RedisClient;
  userTopic: Topic;
  waiting: any[];
  cfg: any;
  userService: any;
  constructor(private logger: Logger, opts: AccessControlConfiguration,
    userTopic: Topic, cfg: any, userService: any) {
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
    this.cfg = cfg;
    const redisConfig = this.cfg.get('redis');
    redisConfig.db = this.cfg.get('redis:db-indexes:db-subject');
    this.redisClient = createClient(redisConfig);
    this.userTopic = userTopic;
    this.waiting = [];
    this.userService = userService;
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

    let effect: EffectEvaluation;
    let context = request.context;
    if (context && context.subject && context.subject.token) {
      const user = await this.userService.findByToken({ token: context.subject.token });
      if (user && user.data) {
        request.context.subject.id = user.data.id;
        request.context.subject.tokens = user.data.tokens;
        request.context.subject.role_associations = user.data.role_associations;
      }
    }
    for (let [, value] of this.policySets) {
      const policySet: PolicySet = value;
      let policyEffects: EffectEvaluation[] = [];

      if ((!!policySet.target && await this.targetMatches(policySet.target, request))
        || !policySet.target) {
        let exactMatch = false;
        for (let [, policyValue] of policySet.combinables) {
          const policy: Policy = policyValue;
          if (!!policy.target && await this.targetMatches(policy.target, request)) {
            exactMatch = true;
            break;
          }
        }

        for (let [, policyValue] of policySet.combinables) {
          const policy: Policy = policyValue;

          const ruleEffects: EffectEvaluation[] = [];
          if ((!!policy.target && exactMatch && await this.targetMatches(policy.target, request))
            // regex match
            || (!!policy.target && !exactMatch && await this.targetMatches(policy.target, request, 'isAllowed', true))
            || !policy.target) {

            const rules: Map<string, Rule> = policy.combinables;
            this.logger.verbose(`Checking policy ${policy.name}...`);
            // only apply a policy effect if there are no rules
            // combine rules otherwise
            if (rules.size == 0 && !!policy.effect) {
              policyEffects.push({ effect: policy.effect, evaluation_cacheable: policy.evaluation_cacheable });
            }

            else {
              for (let [, rule] of policy.combinables) {
                let evaluation_cacheable = rule.evaluation_cacheable;
                // if rule has not target it should be always applied inside the policy scope
                this.logger.verbose(`Checking rule target and request target for ${rule.name}`);
                let matches = !rule.target || await this.targetMatches(rule.target, request, 'isAllowed', true);

                if (matches) {
                  this.logger.verbose(`Checking rule ${rule.name}`);
                  if (matches && rule.target) {
                    matches = await checkHierarchicalScope(rule.target, request, this.urns, this);
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
                            obligation: '',
                            evaluation_cacheable
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
                      obligation: '',
                      evaluation_cacheable
                    };
                  }

                  if (matches) {
                    ruleEffects.push({ effect: rule.effect, evaluation_cacheable });
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
        obligation: '',
        evaluation_cacheable: undefined
      };
    }

    let decision: Decision;

    decision = Decision[effect.effect] || Decision.INDETERMINATE;

    this.logger.silly('Access response is', decision);
    return {
      decision,
      obligation: '',
      evaluation_cacheable: effect.evaluation_cacheable
    };
  }

  async whatIsAllowed(request: Request): Promise<PolicySetRQ[]> {
    let policySets: PolicySetRQ[] = [];
    let context = request.context;
    if (context && context.subject && context.subject.token) {
      const user = await this.userService.findByToken({ token: context.subject.token });
      if (user && user.data) {
        request.context.subject.id = user.data.id;
        request.context.subject.tokens = user.data.tokens;
        request.context.subject.role_associations = user.data.role_associations;
      }
    }
    for (let [, value] of this.policySets) {
      let pSet: PolicySetRQ;
      if (_.isEmpty(value.target) || await this.targetMatches(value.target, request)) {
        pSet = _.merge({}, { combining_algorithm: value.combiningAlgorithm }, _.pick(value, ['id', 'target', 'effect']));
        pSet.policies = [];

        let exactMatch = false;
        for (let [, policy] of value.combinables) {
          if (!!policy.target && await this.targetMatches(policy.target, request)) {
            exactMatch = true;
            break;
          }
        }

        for (let [, policy] of value.combinables) {
          let policyRQ: PolicyRQ;
          if (_.isEmpty(policy.target)
            || (exactMatch && await this.targetMatches(policy.target, request))
            || (!exactMatch && await this.targetMatches(policy.target, request, 'whatIsAllowed', true))) {
            policyRQ = _.merge({}, { combining_algorithm: policy.combiningAlgorithm }, _.pick(policy, ['id', 'target', 'effect', 'evaluation_cacheable']));
            policyRQ.rules = [];

            policyRQ.has_rules = (!!policy.combinables && policy.combinables.size > 0);

            for (let [, rule] of policy.combinables) {
              let ruleRQ: RuleRQ;
              if (_.isEmpty(rule.target) || await this.targetMatches(rule.target, request, 'whatIsAllowed', true)) {
                ruleRQ = _.merge({}, { context_query: rule.contextQuery }, _.pick(rule, ['id', 'target', 'effect', 'condition', 'evaluation_cacheable']));
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
  private async targetMatches(ruleTarget: Target, request: Request,
    operation: AccessControlOperation = 'isAllowed', regexMatch?: boolean): Promise<boolean> {
    const requestTarget = request.target;
    const subMatch = await this.checkSubjectMatches(ruleTarget.subject, requestTarget.subject, request);
    const subMatches = (operation == 'whatIsAllowed' && _.isEmpty(requestTarget.subject))
      || subMatch;

    const match = subMatches && this.attributesMatch(ruleTarget.action, requestTarget.action);
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
              } else if (regexMatch && reqAttribute.id == urn) {
                // rule entity
                const value = attribute.value;
                let pattern = value.substring(value.lastIndexOf(':') + 1);
                let nsEntityArray = pattern.split('.');
                // firstElement could be either entity or namespace
                let nsOrEntity = nsEntityArray[0];
                let entityRegexValue = nsEntityArray[nsEntityArray.length - 1];
                let reqNS, ruleNS;
                if (nsOrEntity.toUpperCase() != entityRegexValue.toUpperCase()) {
                  // rule name space is present
                  ruleNS = nsOrEntity.toUpperCase();
                }
                // request entity
                let reqValue = reqAttribute.value;
                let reqPattern = reqValue.substring(reqValue.lastIndexOf(':') + 1);
                let reqNSEntityArray = reqPattern.split('.');
                // firstElement could be either entity or namespace
                let reqNSOrEntity = reqNSEntityArray[0];
                let requestEntityValue = reqNSEntityArray[reqNSEntityArray.length - 1];
                if (reqNSOrEntity.toUpperCase() != requestEntityValue.toUpperCase()) {
                  // request name space is present
                  reqNS = reqNSOrEntity.toUpperCase();
                }

                if ((reqNS && ruleNS && (reqNS === ruleNS)) || (!reqNS && !ruleNS)) {
                  const reExp = new RegExp(entityRegexValue);
                  if (reqAttribute.value.match(reExp)) {
                    return true;
                  }
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
        return this.attributesMatch(ruleTarget.resources, requestTarget.resources, regexMatch);
    }
  }

  /**
   * Check if the attributes of a action or resources from a rule, policy
   * or policy set match the attributes from a request.
   *
   * @param ruleAttributes
   * @param requestAttributes
   */
  private attributesMatch(ruleAttributes: Attribute[], requestAttributes: Attribute[],
    regexMatch?: boolean): boolean {

    for (let attribute of ruleAttributes) {
      const id = attribute.id;
      const value = attribute.value;
      const match = !!requestAttributes.find((requestAttribute) => {
        // return requestAttribute.id == id && requestAttribute.value == value;
        if (requestAttribute.id == id && requestAttribute.value == value) {
          return true;
        } else if (regexMatch && requestAttribute.id == id) {
          // rule entity
          let pattern = value.substring(value.lastIndexOf(':') + 1);
          let nsEntityArray = pattern.split('.');
          // firstElement could be either entity or namespace
          let nsOrEntity = nsEntityArray[0];
          let entityRegexValue = nsEntityArray[nsEntityArray.length - 1];
          let reqNS, ruleNS;
          if (nsOrEntity.toUpperCase() != entityRegexValue.toUpperCase()) {
            // rule name space is present
            ruleNS = nsOrEntity.toUpperCase();
          }

          // request entity
          let reqValue = requestAttribute.value;
          let reqPattern = reqValue.substring(reqValue.lastIndexOf(':') + 1);
          let reqNSEntityArray = reqPattern.split('.');
          // firstElement could be either entity or namespace
          let reqNSOrEntity = reqNSEntityArray[0];
          let requestEntityValue = reqNSEntityArray[reqNSEntityArray.length - 1];
          if (reqNSOrEntity.toUpperCase() != requestEntityValue.toUpperCase()) {
            // request name space is present
            reqNS = reqNSOrEntity.toUpperCase();
          }

          if ((reqNS && ruleNS && (reqNS === ruleNS)) || (!reqNS && !ruleNS)) {
            const reExp = new RegExp(entityRegexValue);
            if (requestAttribute.value.match(reExp)) {
              return true;
            }
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

  async getRedisKey(key: string): Promise<any> {
    return new Promise((resolve, reject) => {
      if (!key) {
        this.logger.info('Key not defined');
        resolve();
      }
      this.redisClient.get(key, async (err, reply) => {
        if (err) {
          reject(err);
          return;
        }

        if (reply) {
          this.logger.debug('Found key in cache: ' + key);
          resolve(JSON.parse(reply));
          return;
        }
        if (!err && !reply) {
          this.logger.info('Key does not exist', { key });
          resolve();
        }
      });
    });
  }

  async evictHRScopes(subID: string): Promise<void> {
    const key = `cache:${subID}:*`;
    return new Promise((resolve, reject) => {
      this.redisClient.keys(key, async (err, reply) => {
        if (err) {
          reject(err);
          return;
        }

        if (reply && reply.length) {
          this.redisClient.del(reply, (err1) => {
            if (err1) {
              reject(err1);
              return;
            }
            this.logger.debug('Evicted Subject cache: ' + key);
            resolve();
          });
        }
      });
    });
  }

  async setRedisKey(key: string, value: any): Promise<any> {
    new Promise((resolve, reject) => {
      this.redisClient.set(key, value, (err, res) => {
        if (err) {
          this.logger.error('Error writing to Subject cache:', err);
          reject(err);
          return;
        }
        if (res) {
          this.logger.info(`Subject ${key} updated`);
          resolve(value);
          return;
        }
        if (!err && !res) {
          this.logger.info('Key does not exist', { key });
          resolve();
        }
      });
    }).catch((err) => {
      this.logger.error('Error updating Subject cache:', err);
    });
  }

  async  createHRScope(context) {
    if (context && !context.subject) {
      context.subject = {};
    }
    const token = context.subject.token;
    const subjectID = context.subject.id;
    const subjectTokens = context.subject.tokens;
    const tokenFound = _.find(subjectTokens, { token });
    let redisHRScopesKey;
    if (tokenFound && tokenFound.interactive) {
      redisHRScopesKey = `cache:${subjectID}:hrScopes`;
    } else if (tokenFound && !tokenFound.interactive) {
      redisHRScopesKey = `cache:${subjectID}:${token}:hrScopes`;
    }
    let timeout = this.cfg.get('authorization:hrReqTimeout');
    if (!timeout) {
      timeout = 300000;
    }
    let hrScopes: any;
    try {
      hrScopes = await this.getRedisKey(redisHRScopesKey);
    } catch (err) {
      this.logger.info(`Subject or HR Scope not persisted in redis in acs`);
    }

    if (_.isEmpty(hrScopes)) {
      const date = new Date().toISOString();
      const tokenDate = token + ':' + date;
      await this.userTopic.emit('hierarchicalScopesRequest', { token: tokenDate });
      this.waiting[tokenDate] = [];
      try {
        await new Promise((resolve, reject) => {
          const timeoutId = setTimeout(async () => {
            reject({ message: 'hr scope read timed out', tokenDate });
          }, timeout);
          this.waiting[tokenDate].push({ resolve, reject, timeoutId });
        });
      } catch (err) {
        // unhandled promise rejection for timeout
        this.logger.error(`Error creating Hierarchical scope for subject ${tokenDate}`);
      }
      const subjectHRScopes = await this.getRedisKey(redisHRScopesKey);
      Object.assign(context.subject, { hierarchical_scopes: subjectHRScopes });
    } else {
      Object.assign(context.subject, { hierarchical_scopes: hrScopes });
    }
    return context;
  }

  /**
   * Check if the attributes of subject from a rule, policy
   * or policy set match the attributes from a request.
   *
   * @param ruleAttributes
   * @param requestSubAttributes
   */
  private async checkSubjectMatches(ruleSubAttributes: Attribute[],
    requestSubAttributes: Attribute[], request: Request): Promise<boolean> {
    // 1) Check if the rule subject entity exists, if so then check
    // request->target->subject->orgInst or roleScopeInst matches with
    // context->subject->role_associations->roleScopeInst or hierarchical_scope
    // 2) if 1 is true then subject match is considered
    // 3) If rule subject entity does not exist (as for master data resources)
    // then check context->subject->role_associations->role against
    // Rule->subject->role
    const scopingEntityURN = this.urns.get('roleScopingEntity');
    const scopingInstanceURN = this.urns.get('roleScopingInstance');
    const hierarchicalRoleScopingURN = this.urns.get('hierarchicalRoleScoping');
    const roleURN = this.urns.get('role');
    let matches = false;
    let scopingEntExists = false;
    let ruleRole;
    // default if hierarchicalRoleScopingURN is not configured then consider
    // to match the HR scopes
    let hierarchicalRoleScoping = 'true';
    if (ruleSubAttributes && ruleSubAttributes.length === 0) {
      matches = true;
      return matches;
    }
    for (let ruleSubAttribute of ruleSubAttributes) {
      if (ruleSubAttribute.id === scopingEntityURN) {
        // match the scoping entity value
        scopingEntExists = true;
        for (let requestSubAttribute of requestSubAttributes) {
          if (requestSubAttribute.value === ruleSubAttribute.value) {
            matches = true;
            break;
          }
        }
      } else if (ruleSubAttribute.id === roleURN) {
        ruleRole = ruleSubAttribute.value;
      } else if (ruleSubAttribute.id === hierarchicalRoleScopingURN) {
        hierarchicalRoleScoping = ruleSubAttribute.value;
      }
    }

    let context = request.context;
    // check if context subject_id contains HR scope if not make request 'createHierarchicalScopes'
    if (context && context.subject && context.subject.token &&
      _.isEmpty(context.subject.hierarchical_scopes)) {
      context = await this.createHRScope(context);
    }

    if (scopingEntExists && matches) {
      matches = false;
      // check the target scoping instance is present in
      // the context subject roleassociations and then update matches to true
      const context = request.context;
      if (context && context.subject && context.subject.role_associations) {
        for (let requestSubAttribute of requestSubAttributes) {
          if (requestSubAttribute.id === scopingInstanceURN) {
            const targetScopingInstance = requestSubAttribute.value;
            // check in role_associations
            const userRoleAssocs = context.subject.role_associations;
            if (!_.isEmpty(userRoleAssocs)) {
              for (let role of userRoleAssocs) {
                const roleID = role.role;
                const attributes = role.attributes;
                for (let attribute of attributes) {
                  if (attribute.id === scopingInstanceURN &&
                    attribute.value === targetScopingInstance) {
                    if (!ruleRole || (ruleRole && ruleRole === roleID)) {
                      matches = true;
                      return matches;
                    }
                  }
                }
              }
            }
            if (!matches && hierarchicalRoleScoping && hierarchicalRoleScoping === 'true') {
              // check for HR scope
              const hrScopes = context.subject.hierarchical_scopes;
              if (!hrScopes || hrScopes.length === 0) {
                return matches;
              }
              for (let hrScope of hrScopes) {
                if (this.checkTargetInstanceExists(hrScope, targetScopingInstance)) {
                  const userRoleAssocs = context.subject.role_associations;
                  if (!_.isEmpty(userRoleAssocs)) {
                    for (let role of userRoleAssocs) {
                      const roleID = role.role;
                      if (!ruleRole || (ruleRole && ruleRole === roleID)) {
                        matches = true;
                        return matches;
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    } else if (!scopingEntExists) {
      // scoping entity does not exist - check for point 3.
      if (request.context && request.context.subject) {
        const userRoleAssocs = request.context.subject.role_associations;
        if (!_.isEmpty(userRoleAssocs)) {
          for (let ruleSubAttribute of ruleSubAttributes) {
            if (ruleSubAttribute.id === roleURN) {
              for (let userRoleAssoc of userRoleAssocs) {
                if (userRoleAssoc.role === ruleSubAttribute.value) {
                  matches = true;
                  return matches;
                }
              }
            }
          }
        }
      }
      // must be a rule subject targetted to specific user
      if (!matches && this.attributesMatch(ruleSubAttributes, requestSubAttributes)) {
        return true;
      }
      return false;
    }
    return matches;
  }

  private checkTargetInstanceExists(hrScope: HierarchicalScope,
    targetScopingInstance: string): boolean {
    if (hrScope.id === targetScopingInstance) {
      return true;
    } else {
      if (hrScope.children) {
        for (let child of hrScope.children) {
          if (this.checkTargetInstanceExists(child, targetScopingInstance)) {
            return true;
          }
        }
      }
    }
  }

  /**
   * A list of rules or policies provides a list of Effects.
   * This method is invoked to evaluate the final effect
   * according to a combining algorithm
   * @param combiningAlgorithm
   * @param effects
   */
  private decide(combiningAlgorithm: string, effects: EffectEvaluation[]): EffectEvaluation {
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
  protected denyOverrides(effects: EffectEvaluation[]): EffectEvaluation {
    let effect, evaluation_cacheable;
    for (let effectObj of effects) {
      if (effectObj.effect === Effect.DENY) {
        effect = effectObj.effect;
        evaluation_cacheable = effectObj.evaluation_cacheable;
        break;
      } else {
        effect = effectObj.effect;
        evaluation_cacheable = effectObj.evaluation_cacheable;
      }
    }
    return {
      effect,
      evaluation_cacheable
    };
  }

  /**
   * Always PERMIT if PERMIT exists;
   * @param effects
   */
  protected permitOverrides(effects: EffectEvaluation[]): EffectEvaluation {
    let effect, evaluation_cacheable;
    for (let effectObj of effects) {
      if (effectObj.effect === Effect.PERMIT) {
        effect = effectObj.effect;
        evaluation_cacheable = effectObj.evaluation_cacheable;
        break;
      } else {
        effect = effectObj.effect;
        evaluation_cacheable = effectObj.evaluation_cacheable;
      }
    }
    return {
      effect,
      evaluation_cacheable
    };
  }

  /**
   * Apply first effect which matches PERMIT or DENY.
   * Note that in a future implementation Effect may be extended to further values.
   * @param effects
   */
  protected firstApplicable(effects: EffectEvaluation[]): EffectEvaluation {
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
