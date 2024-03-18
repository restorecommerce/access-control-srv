import _ from 'lodash-es';
import {
  PolicySetWithCombinables, PolicyWithCombinables, AccessControlOperation,
  CombiningAlgorithm, AccessControlConfiguration, EffectEvaluation, ContextWithSubResolved
} from './interfaces.js';
import { Request, Response, Response_Decision, ReverseQuery } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/access_control.js';
import { Rule, RuleRQ, ContextQuery, Effect, Target } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/rule.js';
import { Policy, PolicyRQ } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/policy.js';
import { PolicySetRQ } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/policy_set.js';
import { Attribute } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/attribute.js';
import { HierarchicalScope } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/auth.js';
import {
  UserServiceClient
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/user.js';

import { ResourceAdapter } from './resource_adapters/adapter.js';
import { GraphQLAdapter } from './resource_adapters/gql.js';
import * as errors from './errors.js';
import { checkHierarchicalScope } from './hierarchicalScope.js';
import { Logger } from 'winston';
import { createClient, RedisClientType } from 'redis';
import { Topic } from '@restorecommerce/kafka-client';
import { verifyACLList } from './verifyACL.js';
import { conditionMatches } from './utils.js';

export class AccessController {
  policySets: Map<string, PolicySetWithCombinables>;
  combiningAlgorithms: Map<string, any>;
  urns: Map<string, string>;
  resourceAdapter: ResourceAdapter;
  redisClient: RedisClientType<any, any>;
  userTopic: Topic;
  waiting: any;
  cfg: any;
  userService: UserServiceClient;

  constructor(
    private logger: Logger,
    opts: AccessControlConfiguration,
    userTopic: Topic,
    cfg: any,
    userService: UserServiceClient
  ) {
    this.policySets = new Map<string, PolicySetWithCombinables>();
    this.combiningAlgorithms = new Map<string, any>();

    logger.info('Parsing combining algorithms from access control configuration...');
    //  parsing URNs and mapping them to functions
    const combiningAlgorithms: CombiningAlgorithm[] = opts?.combiningAlgorithms ?? [];
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
    redisConfig.database = this.cfg.get('redis:db-indexes:db-subject');
    this.redisClient = createClient(redisConfig);
    this.redisClient.on('error', (err) => logger.error('Redis Client Error', { code: err.code, message: err.message, stack: err.stack }));
    this.redisClient.connect().then(data => logger.info('Redis client for subject cache connection successful')).catch(err => {
      logger.error('Error creating redis client instance', { code: err.code, message: err.message, stack: err.stack });
    });
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
      return {
        decision: Response_Decision.DENY,
        evaluation_cacheable: false, // typing for evaluation_cachecable expected so adding default false
        obligations: [],
        operation_status: {
          code: 400,
          message: 'Access request had no target. Skipping request'
        }
      };
    }

    let effect: EffectEvaluation;
    let obligations: Attribute[] = [];
    let context = (request as any).context as ContextWithSubResolved;
    if (!context) {
      (context as any) = {};
    }
    if (context?.subject?.token) {
      const subject = await this.userService.findByToken({ token: context.subject.token });
      if (subject?.payload) {
        context.subject.id = subject.payload.id;
        (context.subject as any).tokens = subject.payload.tokens;
        context.subject.role_associations = subject.payload.role_associations;
      }
    }
    for (let [, value] of this.policySets) {
      const policySet: PolicySetWithCombinables = value;
      let policyEffects: EffectEvaluation[] = [];

      // policyEffect needed to evalute if the properties should be PERMIT / DENY
      let policyEffect: Effect;
      if (
        !policySet.target
        || await this.targetMatches(policySet.target, request, 'isAllowed', obligations)
      ) {
        let exactMatch = false;
        for (let [, policyValue] of policySet.combinables) {
          const policy: Policy = policyValue;
          if (policy.effect) {
            policyEffect = policy.effect;
          }
          else if (policy.combining_algorithm) {
            const method = this.combiningAlgorithms.get(policy.combining_algorithm);
            if (method === 'permitOverrides') {
              policyEffect = Effect.PERMIT;
            } else if (method === 'denyOverrides') {
              policyEffect = Effect.DENY;
            }
          }

          if (
            policy.target
            && await this.targetMatches(policy.target, request, 'isAllowed', obligations, policyEffect)
          ) {
            exactMatch = true;
            break;
          }
        }

        // if there are multiple entities in the request.target.resources
        // and if exactMatch is true, then check again with the resourcesAttributeMatch providing one entity each time
        // to ensure there is an exact policy entity match for each of the requested entity
        const entityURN = this.urns.get('entity');
        if (exactMatch && request?.target?.resources?.filter(att => att?.id === entityURN)?.length > 1) {
          exactMatch = this.checkMultipleEntitiesMatch(value, request, obligations);
        }

        for (let [, policyValue] of policySet.combinables) {
          const policy: PolicyWithCombinables = policyValue;
          if (!policy) {
            this.logger.debug('Policy Object not set');
            continue;
          }
          const ruleEffects: EffectEvaluation[] = [];
          if (
            !policy.target
            || (
              exactMatch
              && await this.targetMatches(policy.target, request, 'isAllowed', obligations, policyEffect)
            )
            // regex match
            || (
              !exactMatch
              && await this.targetMatches(policy.target, request, 'isAllowed', obligations, policyEffect, true)
            )
          ) {
            const rules: Map<string, Rule> = policy.combinables;
            this.logger.verbose(`Checking policy ${policy.name}`);
            // only apply a policy effect if there are no rules
            // combine rules otherwise
            if (rules.size == 0 && !!policy.effect) {
              policyEffects.push({ effect: policy.effect, evaluation_cacheable: policy.evaluation_cacheable });
            }
            else {
              let evaluationCacheableRule = true;
              for (let [, rule] of policy.combinables) {
                if (!rule) {
                  this.logger.debug('Rule Object not set');
                  continue;
                }
                let evaluation_cacheable = rule.evaluation_cacheable;
                if (!evaluation_cacheable) {
                  evaluationCacheableRule = false;
                }
                // if rule has not target it should be always applied inside the policy scope
                this.logger.verbose(`Checking rule target and request target for ${rule.name}`);
                let matches = !rule.target || await this.targetMatches(rule.target, request, 'isAllowed', obligations, rule.effect);

                // check for regex if there is no direct match
                if (!matches) {
                  matches = await this.targetMatches(rule.target, request, 'isAllowed', obligations, rule.effect, true);
                }

                if (matches) {
                  this.logger.verbose(`Checking rule HR Scope for ${rule.name}`);
                  if (matches && rule.target) {
                    matches = await checkHierarchicalScope(rule.target, request, this.urns, this, this.logger);
                  }

                  try {
                    if (matches && rule.condition?.length) {
                      // context query is only checked when a rule exists
                      let context: any;
                      if (
                        this.resourceAdapter
                        && (
                          rule.context_query?.filters?.length
                          || rule.context_query?.query?.length
                        )
                      ) {
                        context = await this.pullContextResources(rule.context_query, request);

                        if (_.isNil(context)) {
                          this.logger.debug('Context query response is empty!');
                          return {  // deny by default
                            decision: Response_Decision.DENY,
                            obligations,
                            evaluation_cacheable,
                            operation_status: {
                              code: 200,
                              message: 'success'
                            }
                          };
                        }
                      }

                      request.context = context ?? request.context;
                      this.logger.debug('Validating rule condition', { name: rule.name, condition: rule.condition });
                      matches = conditionMatches(rule.condition, request);
                      this.logger.debug('condition validation response', { matches });
                    }
                  } catch (err: any) {
                    this.logger.error('Caught an exception while applying rule condition to request', { code: err.code, message: err.message, stack: err.stack });
                    return {  // if an exception is caught deny by default
                      decision: Response_Decision.DENY,
                      obligations,
                      evaluation_cacheable,
                      operation_status: {
                        code: err.code ? err.code : 500,
                        message: err.message
                      }
                    };
                  }

                  // check if request has an ACL property set, if so verify it with the current rule target
                  if (matches && rule?.target) {
                    matches = await verifyACLList(rule.target, request, this.urns, this, this.logger);
                  }

                  if (matches) {
                    if (!evaluationCacheableRule) {
                      evaluation_cacheable = evaluationCacheableRule;
                    }
                    ruleEffects.push({ effect: rule.effect, evaluation_cacheable });
                  }
                }
              }

              if (ruleEffects?.length > 0) {
                policyEffects.push(this.decide(policy.combining_algorithm, ruleEffects));
              }
            }
          }
        }

        if (policyEffects?.length > 0) {
          effect = this.decide(policySet.combining_algorithm, policyEffects);
        }
      }
    }

    if (!effect) {
      this.logger.silly('Access response is INDETERMINATE');
      return {
        decision: Response_Decision.INDETERMINATE,
        obligations,
        evaluation_cacheable: undefined,
        operation_status: {
          code: 200,
          message: 'success'
        }
      };
    }

    let decision: Response_Decision;
    decision = Response_Decision[effect.effect] || Response_Decision.INDETERMINATE;

    this.logger.silly('Access response is', decision);
    return {
      decision,
      obligations,
      evaluation_cacheable: effect.evaluation_cacheable,
      operation_status: {
        code: 200,
        message: 'success'
      }
    };
  }

  async whatIsAllowed(request: Request): Promise<ReverseQuery> {
    let policySets: PolicySetRQ[] = [];
    let context = (request as any).context as ContextWithSubResolved;
    if (context?.subject?.token) {
      const subject = await this.userService.findByToken({ token: context.subject.token });
      if (subject?.payload) {
        context.subject.id = subject.payload.id;
        (context.subject as any).tokens = subject.payload.tokens;
        context.subject.role_associations = subject.payload.role_associations;
      }
    }
    let obligations: Attribute[] = [];
    for (let [, value] of this.policySets) {
      let pSet: PolicySetRQ;
      if (
        _.isEmpty(value.target)
        || await this.targetMatches(value.target, request, 'whatIsAllowed', obligations)
      ) {
        pSet = _.merge({}, { combining_algorithm: value.combining_algorithm }, _.pick(value, ['id', 'target', 'effect'])) as any;
        pSet.policies = [];

        let exactMatch = false;
        let policyEffect: Effect;
        for (let [, policy] of value.combinables) {
          if (policy.effect) {
            policyEffect = policy.effect;
          } else if (policy?.combining_algorithm) {
            const method = this.combiningAlgorithms.get(policy.combining_algorithm);
            if (method === 'permitOverrides') {
              policyEffect = Effect.PERMIT;
            } else if (method === 'denyOverrides') {
              policyEffect = Effect.DENY;
            }
          }
          if (!!policy.target && await this.targetMatches(policy.target, request, 'whatIsAllowed', obligations, policyEffect)) {
            exactMatch = true;
            break;
          }
        }

        // if there are multiple entities in the request.target.resources
        // and if exactMatch is true, then check again with the resourcesAttributeMatch providing one entity each time
        // to ensure there is an exact policy entity match for each of the requested entity
        const entityURN = this.urns.get('entity');
        if (exactMatch && request?.target?.resources?.filter(att => att?.id === entityURN)?.length > 1) {
          exactMatch = this.checkMultipleEntitiesMatch(value, request, obligations);
        }

        for (let [, policy] of value.combinables) {
          let policyRQ: PolicyRQ;
          if (!policy) {
            this.logger.debug('Policy Object not set');
            continue;
          }
          if (_.isEmpty(policy.target)
            || (exactMatch && await this.targetMatches(policy.target, request, 'whatIsAllowed', obligations, policyEffect))
            || (!exactMatch && await this.targetMatches(policy.target, request, 'whatIsAllowed', obligations, policyEffect, true))) {
            policyRQ = _.merge({}, { combining_algorithm: policy.combining_algorithm }, _.pick(policy, ['id', 'target', 'effect', 'evaluation_cacheable'])) as any;
            policyRQ.rules = [];

            policyRQ.has_rules = (!!policy.combinables && policy.combinables.size > 0);

            for (let [, rule] of policy.combinables) {
              if (!rule) {
                this.logger.debug('Rule Object not set');
                continue;
              }
              let ruleRQ: RuleRQ;
              this.logger.debug(`WhatIsAllowed Checking rule target and request target for ${rule.name}`);
              let matches = _.isEmpty(rule.target) || await this.targetMatches(rule.target, request, 'whatIsAllowed', obligations, rule.effect);
              // check for regex if there is no direct match
              if (!matches) {
                matches = await this.targetMatches(rule.target, request, 'whatIsAllowed', obligations, rule.effect, true);
              }

              if (_.isEmpty(rule.target) || matches) {
                ruleRQ = _.merge({}, { context_query: rule.context_query }, _.pick(rule, ['id', 'target', 'effect', 'condition', 'evaluation_cacheable']));
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
    return {
      policy_sets: policySets, obligations, operation_status: {
        code: 200,
        message: 'success'
      }
    };
  }

  private checkMultipleEntitiesMatch(policySet: PolicySetWithCombinables, request: Request, obligation: Attribute[]): boolean {
    let multipleEntitiesMatch = false;
    let exactMatch = true;
    // iterate and find for each of the exact mathing resource attribute
    const entityURN = this.urns.get('entity');
    for (let requestAttributeObj of request?.target?.resources || []) {
      if (requestAttributeObj.id === entityURN) {
        multipleEntitiesMatch = false;
        for (let [, policyValue] of policySet.combinables) {
          const policy: Policy = policyValue;
          let policyEffect: Effect;
          if (policy.effect) {
            policyEffect = policy.effect;
          } else if (policy.combining_algorithm) {
            const method = this.combiningAlgorithms.get(policy.combining_algorithm);
            if (method === 'permitOverrides') {
              policyEffect = Effect.PERMIT;
            } else if (method === 'denyOverrides') {
              policyEffect = Effect.DENY;
            }
          }
          if (policy?.target?.resources?.length > 0) {
            if (this.resourceAttributesMatch(policy?.target?.resources, [requestAttributeObj], 'isAllowed', obligation, policyEffect)) {
              multipleEntitiesMatch = true;
            }
          }
        }
        if (!multipleEntitiesMatch) {
          exactMatch = false; // reset exact match even if one of the multiple entities exact match is not found
          break;
        }
      }
    }
    return exactMatch;
  }

  private resourceAttributesMatch(ruleAttributes: Attribute[],
    requestAttributes: Attribute[], operation: AccessControlOperation,
    maskPropertyList: Attribute[], effect: Effect, regexMatch?: boolean): boolean {
    const entityURN = this.urns.get('entity');
    const propertyURN = this.urns.get('property');
    const maskedPropertyURN = this.urns.get('maskedProperty');
    const operationURN = this.urns.get('operation');
    let entityMatch = false;
    let propertyMatch = false;
    let rulePropertiesExist = false;
    let requestPropertiesExist = false;
    let operationMatch = false;
    let requestEntityURN = '';
    let skipDenyRule = true;
    let rulePropertyValue = '';
    // if there are no resources defined in rule or policy, return as resources match
    if (_.isEmpty(ruleAttributes)) {
      return true;
    }
    if (!maskPropertyList) {
      maskPropertyList = [];
    }
    for (let reqAttr of requestAttributes || []) {
      if (reqAttr.id === propertyURN) {
        requestPropertiesExist = true;
      }
    }
    for (let requestAttribute of requestAttributes || []) {
      propertyMatch = false;
      for (let ruleAttribute of ruleAttributes || []) {
        if (ruleAttribute.id === propertyURN) {
          rulePropertiesExist = true;
          rulePropertyValue = ruleAttribute.value;
        }
        // direct match for attribute values
        if (!regexMatch) {
          if (requestAttribute?.id === entityURN && ruleAttribute?.id === entityURN
            && requestAttribute?.value === ruleAttribute?.value) {
            // entity match
            entityMatch = true;
            requestEntityURN = requestAttribute.value;
          } else if (requestAttribute?.id === operationURN && ruleAttribute?.id === operationURN
            && requestAttribute?.value === ruleAttribute?.value) {
            operationMatch = true;
          } else if (entityMatch && requestAttribute?.id === propertyURN &&
            ruleAttribute?.id === propertyURN) {
            // check if requestEntityURNs entityName is part in the ruleAttribute property
            // if so check the rule attribute value and request attribute value, if not set property match for
            // this request property as true as it does not belong to this rule (since for multiple entities request
            // its possible that there could be properties from other entities)
            const entityName = requestEntityURN?.substring(requestEntityURN?.lastIndexOf(':') + 1);
            if (requestAttribute?.value?.indexOf(entityName) > -1) {
              // if match for request attribute is not found in rule attribute, Deny for isAllowed
              // and add properties to maskPropertyList for WhatIsAllowed
              if (ruleAttribute?.value === requestAttribute?.value) {
                propertyMatch = true;
              }
            } else if (effect === Effect.PERMIT) { // set propertyMatch to true only when rule is Permit and request does not belong to this rule
              propertyMatch = true; // the requested entity property does not belong to this rule
            }
          }
        } else if (regexMatch) {
          // regex match for attribute values
          if (requestAttribute?.id === entityURN && ruleAttribute?.id === entityURN) {
            // rule entity, get ruleNS and entityRegexValue for rule
            const value = ruleAttribute?.value;
            let pattern = value?.substring(value?.lastIndexOf(':') + 1);
            let nsEntityArray = pattern?.split('.');
            // firstElement could be either entity or namespace
            let nsOrEntity = nsEntityArray[0];
            let entityRegexValue = nsEntityArray[nsEntityArray?.length - 1];
            let reqNS, ruleNS;
            if (nsOrEntity?.toUpperCase() != entityRegexValue?.toUpperCase()) {
              // rule name space is present
              ruleNS = nsOrEntity.toUpperCase();
            }

            // request entity, get reqNS and requestEntityValue for request
            let reqValue = requestAttribute?.value;
            requestEntityURN = reqValue;
            const reqAttributeNS = reqValue?.substring(0, reqValue?.lastIndexOf(':'));
            const ruleAttributeNS = value?.substring(0, value?.lastIndexOf(':'));
            // verify namespace before entity name
            if (reqAttributeNS != ruleAttributeNS) {
              entityMatch = false;
            }
            let reqPattern = reqValue?.substring(reqValue?.lastIndexOf(':') + 1);
            let reqNSEntityArray = reqPattern?.split('.');
            // firstElement could be either entity or namespace
            let reqNSOrEntity = reqNSEntityArray[0];
            let requestEntityValue = reqNSEntityArray[reqNSEntityArray?.length - 1];
            if (reqNSOrEntity?.toUpperCase() != requestEntityValue?.toUpperCase()) {
              // request name space is present
              reqNS = reqNSOrEntity.toUpperCase();
            }

            if ((reqNS && ruleNS && (reqNS === ruleNS)) || (!reqNS && !ruleNS)) {
              const reExp = new RegExp(entityRegexValue);
              if (requestEntityValue.match(reExp)) {
                entityMatch = true;
              }
            }
          } else if (entityMatch && requestAttribute?.id === propertyURN && ruleAttribute?.id === propertyURN) {
            // check for matching URN property value
            const rulePropertyValue = ruleAttribute?.value?.substring(ruleAttribute?.value?.lastIndexOf('#') + 1);
            const requestPropertyValue = requestAttribute?.value?.substring(requestAttribute?.value?.lastIndexOf('#') + 1);
            if (rulePropertyValue === requestPropertyValue) {
              propertyMatch = true;
            }
          }
        }
      }

      if (operation === 'isAllowed' && effect === Effect.DENY && (requestAttribute?.id === propertyURN || !requestPropertiesExist)
        && entityMatch && rulePropertiesExist && propertyMatch) {
        skipDenyRule = false; // Deny effect rule to be skipped only if the propertyMatch and effect is DENY
      }

      // if no match is found for the request attribute property in rule ==> this implies this is
      // an additional property in request which should be denied or masked
      if (operation === 'isAllowed' && effect === Effect.PERMIT && (requestAttribute?.id === propertyURN || !requestPropertiesExist)
        && entityMatch && rulePropertiesExist && !propertyMatch) {
        return false;
      }

      // for whatIsAllowed if decision is PERMIT and propertyMatch to false it implies
      // subject has requested additional properties requestAttribute.value add it to the maksPropertyList
      if (operation === 'whatIsAllowed' && effect === Effect.PERMIT && (requestAttribute?.id === propertyURN || !requestPropertiesExist)
        && entityMatch && rulePropertiesExist && !propertyMatch) {
        if (!requestPropertiesExist) {
          return false; // since its not possible to evaluate what properties subject would read
        }
        // since there can be multiple rules for same entity below check is to find if maskPropertyList already
        // contains the entityValue from previous matching rule
        const maskPropExists = maskPropertyList?.find((maskObj) => maskObj?.value === requestEntityURN);
        // for masking if no request properties are specified
        let maskProperty;
        if (requestPropertiesExist && requestAttribute?.value) {
          maskProperty = requestAttribute?.value;
        } else if (!requestPropertiesExist) {
          maskProperty = rulePropertyValue;
        }
        if (maskProperty?.indexOf('#') <= -1) { // validate maskPropertyURN value
          continue;
        }
        if (!maskPropExists) {
          maskPropertyList.push({ id: entityURN, value: requestEntityURN, attributes: [{ id: maskedPropertyURN, value: maskProperty, attributes: [] }] });
        } else {
          maskPropExists.attributes.push({ id: maskedPropertyURN, value: maskProperty, attributes: [] });
        }
      }

      // for whatIsAllowed if decision is deny and propertyMatch to true it implies
      // subject does not have access to the requestAttribute.value add it to the maksPropertyList
      // last condition (propertyMatch || !requestPropertiesExist) -> is to match Deny rule when user does not provide any req props
      if (operation === 'whatIsAllowed' && effect === Effect.DENY && (requestAttribute?.id === propertyURN || !requestPropertiesExist)
        && entityMatch && rulePropertiesExist && (propertyMatch || !requestPropertiesExist)) {
        // since there can be multiple rules for same entity below check is to find if maskPropertyList already
        // contains the entityValue from previous matching rule
        const maskPropExists = maskPropertyList?.find((maskObj) => maskObj.value === requestEntityURN);
        let maskProperty;
        // for masking if no request properties are specified
        if (requestPropertiesExist && requestAttribute?.value) {
          maskProperty = requestAttribute.value;
        } else if (!requestPropertiesExist) {
          maskProperty = rulePropertyValue;
        }
        if (maskProperty?.indexOf('#') <= -1) { // validate maskPropertyURN value
          continue;
        }
        if (!maskPropExists) {
          maskPropertyList.push({ id: entityURN, value: requestEntityURN, attributes: [{ id: maskedPropertyURN, value: maskProperty, attributes: [] }] });
        } else {
          maskPropExists.attributes.push({ id: maskedPropertyURN, value: maskProperty, attributes: [] });
        }
      }
    }

    // skip deny rule property is effective only if ruleProps exist and requestProps exist
    if (skipDenyRule && rulePropertiesExist && requestPropertiesExist && effect === Effect.DENY &&
      operation === 'isAllowed' && !propertyMatch) {
      return false;
    }

    // if there is no entity or no operation match return false
    if (!entityMatch && !operationMatch) {
      return false;
    }
    return true;
  }

  /**
 * Check if a request's target matches a rule, policy or policy set's target.
 * @param targetA
 * @param targetB
 */
  private async targetMatches(ruleTarget: Target, request: Request,
    operation: AccessControlOperation = 'isAllowed', maskPropertyList: Attribute[],
    effect: Effect = Effect.PERMIT, regexMatch?: boolean): Promise<boolean> {
    const requestTarget = request.target;
    const subMatch = await this.checkSubjectMatches(ruleTarget.subjects, requestTarget.subjects, request);
    const match = subMatch && this.attributesMatch(ruleTarget.actions, requestTarget.actions);
    if (!match) {
      return false;
    }
    return this.resourceAttributesMatch(ruleTarget.resources,
      requestTarget.resources, operation, maskPropertyList, effect, regexMatch);
  }

  /**
   * Check if the attributes of a action or resources from a rule, policy
   * or policy set match the attributes from a request.
   *
   * @param ruleAttributes
   * @param requestAttributes
   */
  private attributesMatch(ruleAttributes: Attribute[], requestAttributes: Attribute[]): boolean {
    for (let attribute of ruleAttributes || []) {
      const id = attribute?.id;
      const value = attribute?.value;
      const match = !!requestAttributes?.find((requestAttribute) => {
        // return requestAttribute.id == id && requestAttribute.value == value;
        if (requestAttribute?.id == id && requestAttribute?.value == value) {
          return true;
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
    if (!key) {
      this.logger.info('Key not defined');
      return;
    }
    const redisResponse = await this.redisClient.get(key);
    if (!redisResponse) {
      this.logger.info('Key does not exist', { key });
      return;
    }
    if (redisResponse) {
      this.logger.debug('Found key in cache: ' + key);
      return JSON.parse(redisResponse);
    }
  }

  async evictHRScopes(subID: string): Promise<void> {
    const key = `cache:${subID}:*`;
    const matchingKeys = await this.redisClient.keys(key);
    await this.redisClient.del(matchingKeys);
    this.logger.debug('Evicted Subject cache: ' + key);
    return;
  }

  async setRedisKey(key: string, value: any): Promise<any> {
    if (!key || !value) {
      this.logger.info(`Either key or value for redis set is not defined key: ${key} value: ${value}`);
      return;
    }
    return await this.redisClient.set(key, value);
  }

  async createHRScope(context: ContextWithSubResolved): Promise<ContextWithSubResolved> {
    if (context && !context.subject) {
      context.subject = {};
    }
    const token = context.subject.token;
    const subjectID = context.subject.id;
    const subjectTokens = context.subject.tokens;
    const tokenFound = _.find(subjectTokens ?? [], { token });
    let redisHRScopesKey;
    if (tokenFound?.interactive) {
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
    let keyExist;
    if (redisHRScopesKey) {
      keyExist = await this.redisClient.exists(redisHRScopesKey);
    }
    if (!keyExist) {
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
    const scopingEntityURN = this.urns.get('roleScopingEntity'); // urn:restorecommerce:acs:names:roleScopingEntity
    const scopingInstanceURN = this.urns.get('roleScopingInstance'); // urn:restorecommerce:acs:names:roleScopingInstance
    const hierarchicalRoleScopingURN = this.urns.get('hierarchicalRoleScoping');
    const roleURN = this.urns.get('role');
    let matches = false;
    let scopingEntExists = false;
    let ruleRole;
    // default if hierarchicalRoleScopingURN is not configured then consider
    // to match the HR scopes
    let hierarchicalRoleScoping = 'true';
    if (ruleSubAttributes?.length === 0) {
      matches = true;
      return matches;
    }
    for (let ruleSubAttribute of ruleSubAttributes || []) {
      if (ruleSubAttribute?.id === scopingEntityURN) {
        // match the scoping entity value
        scopingEntExists = true;
        for (let requestSubAttribute of requestSubAttributes || []) {
          if (requestSubAttribute?.value === ruleSubAttribute?.value) {
            matches = true;
            break;
          }
        }
      } else if (ruleSubAttribute?.id === roleURN) {
        ruleRole = ruleSubAttribute.value;
      } else if (ruleSubAttribute?.id === hierarchicalRoleScopingURN) {
        hierarchicalRoleScoping = ruleSubAttribute.value;
      }
    }

    let context = (request as any)?.context as ContextWithSubResolved;
    // check if context subject_id contains HR scope if not make request 'createHierarchicalScopes'
    if (context?.subject?.token &&
      _.isEmpty(context.subject.hierarchical_scopes)) {
      context = await this.createHRScope(context);
    }

    if (scopingEntExists && matches) {
      matches = false;
      // check the target scoping instance is present in
      // the context subject roleassociations and then update matches to true
      if (context?.subject?.role_associations) {
        let targetScopingInstance;
        requestSubAttributes?.find((obj) => {
          if (obj?.id === scopingEntityURN && obj?.attributes?.length > 0) {
            obj?.attributes?.filter((roleScopeInstObj) => {
              if (roleScopeInstObj?.id === scopingInstanceURN) {
                targetScopingInstance = roleScopeInstObj?.value;
              }
            });
          }
        });
        // check in role_associations
        const userRoleAssocs = context?.subject?.role_associations;
        if (userRoleAssocs?.length > 0) {
          for (let role of userRoleAssocs) {
            const roleID = role?.role;
            for (let obj of role.attributes || []) {
              if (obj?.id === scopingEntityURN && obj?.attributes?.length > 0) {
                for (let ruleScopInstObj of obj.attributes) {
                  if (ruleScopInstObj?.id == scopingInstanceURN && ruleScopInstObj?.value == targetScopingInstance) {
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
        if (!matches && hierarchicalRoleScoping && hierarchicalRoleScoping === 'true') {
          // check for HR scope
          const hrScopes = context?.subject?.hierarchical_scopes;
          if (!hrScopes || hrScopes?.length === 0) {
            return matches;
          }
          for (let hrScope of hrScopes || []) {
            if (this.checkTargetInstanceExists(hrScope, targetScopingInstance)) {
              const userRoleAssocs = context?.subject?.role_associations;
              if (!_.isEmpty(userRoleAssocs)) {
                for (let role of userRoleAssocs || []) {
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
    } else if (!scopingEntExists) {
      // scoping entity does not exist - check for point 3.
      if (context?.subject) {
        const userRoleAssocs = context?.subject?.role_associations;
        if (userRoleAssocs?.length > 0) {
          const ruleSubAttributeObj = ruleSubAttributes?.find((obj) => obj.id === roleURN);
          for (let obj of userRoleAssocs) {
            if (obj?.role === ruleSubAttributeObj?.value) {
              matches = true;
              return matches;
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
    if (hrScope?.id === targetScopingInstance) {
      return true;
    } else {
      if (hrScope?.children?.length > 0) {
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

  // Combining algorithms

  /**
  * Always DENY if DENY exists;
  * @param effects
  */
  protected denyOverrides(effects: EffectEvaluation[]): EffectEvaluation {
    let effect, evaluation_cacheable;
    for (let effectObj of effects || []) {
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
    for (let effectObj of effects || []) {
      if (effectObj?.effect === Effect.PERMIT) {
        effect = effectObj.effect;
        evaluation_cacheable = effectObj.evaluation_cacheable;
        break;
      } else {
        effect = effectObj?.effect;
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

  updatePolicySet(policySet: PolicySetWithCombinables): void {
    this.policySets.set(policySet.id, policySet);
  }

  removePolicySet(policySetID: string): void {
    this.policySets.delete(policySetID);
  }

  updatePolicy(policySetID: string, policy: PolicyWithCombinables): void {
    const policySet: PolicySetWithCombinables = this.policySets.get(policySetID);
    if (!_.isNil(policySet)) {
      policySet.combinables.set(policy.id, policy);
    }
  }

  removePolicy(policySetID: string, policyID: string): void {
    const policySet: PolicySetWithCombinables = this.policySets.get(policySetID);
    if (!_.isNil(policySet)) {
      policySet.combinables.delete(policyID);
    }
  }

  updateRule(policySetID: string, policyID: string, rule: Rule): void {
    const policySet: PolicySetWithCombinables = this.policySets.get(policySetID);
    if (!_.isNil(policySet)) {
      const policy: PolicyWithCombinables = policySet.combinables.get(policyID);
      if (!_.isNil(policy)) {
        policy.combinables.set(rule.id, rule);
      }
    }
  }

  removeRule(policySetID: string, policyID: string, ruleID: string): void {
    const policySet: PolicySetWithCombinables = this.policySets.get(policySetID);
    if (!_.isNil(policySet)) {
      const policy: PolicyWithCombinables = policySet.combinables.get(policyID);
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
