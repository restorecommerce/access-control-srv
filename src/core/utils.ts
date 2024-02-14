import _ from 'lodash-es';
import fs from 'node:fs';
import yaml from 'js-yaml';
import { AccessController } from './accessController.js';
import { AuthZAction, accessRequest, PolicySetRQ, DecisionResponse, Operation, PolicySetRQResponse, Obligation, ACSClientContext, Resource } from '@restorecommerce/acs-client';
import { Subject } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/auth.js';
import { Response_Decision } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/access_control.js';
import { createServiceConfig } from '@restorecommerce/service-config';
import { createLogger } from '@restorecommerce/logger';
import { createClient, createChannel } from '@restorecommerce/grpc-client';
import { FilterOp } from '@restorecommerce/resource-base-interface/lib/core/interfaces.js';
import * as uuid from 'uuid';
import nodeEval from 'node-eval';
import { Request } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/access_control.js';
import { Rule, Target, Effect } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/rule.js';
import {
  UserServiceDefinition,
  UserServiceClient
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/user.js';
import { PolicySetWithCombinables, PolicyWithCombinables } from './interfaces.js';
import { RoleAssociation } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/auth.js';
import { Topic } from '@restorecommerce/kafka-client';


export const formatTarget = (target: any): Target => {
  if (!target) {
    return null;
  }

  return {
    subjects: target.subjects ? target.subjects : [],
    resources: target.resources ? target.resources : [],
    actions: target.actions ? target.actions : []
  };
};

export const conditionMatches = (condition: string, request: Request): boolean => {
  condition = condition.replace(/\\n/g, '\n');
  let evalResult = nodeEval(condition, 'condition.js', request);
  if (typeof evalResult === 'function') {
    return evalResult(request);
  } else {
    return evalResult;
  }
};

const loadPolicies = (document: any, accessController: AccessController): AccessController => {
  const policySets = document?.policy_sets ? document.policy_sets : [];

  for (let policySetYaml of policySets) {

    let policies = new Map<string, PolicyWithCombinables>();
    for (let policyYaml of policySetYaml.policies) {

      let rules = new Map<string, Rule>();
      if (policyYaml.rules) {
        for (let ruleYaml of policyYaml.rules) {
          const ruleID = ruleYaml.id;
          const ruleName = ruleYaml.name;
          const ruleDescription: string = ruleYaml.description;
          const ruleTarget = formatTarget(ruleYaml.target);
          const evaluationCacheable = ruleYaml.evaluation_cacheable;

          const effect: Effect = ruleYaml.effect;
          const contextQuery = ruleYaml.context_query;  // may be null
          const condition = ruleYaml.condition; // JS code; may be null

          const rule: Rule = {
            id: ruleID,
            name: ruleName,
            description: ruleDescription,
            target: ruleTarget,
            effect,
            context_query: contextQuery,
            condition,
            evaluation_cacheable: evaluationCacheable
          };
          rules.set(rule.id, rule);
        }
      }

      const policyID = policyYaml.id;
      const policyName = policyYaml.name;
      const policyDescription = policyYaml.description;
      const policyCA = policyYaml.combining_algorithm;
      const policyEffect = policyYaml.effect;
      const policyTarget = formatTarget(policyYaml.target);
      const evaluationCacheable = policyYaml.evaluation_cacheable;

      const policy: PolicyWithCombinables = {
        id: policyID,
        name: policyName,
        description: policyDescription,
        combining_algorithm: policyCA,
        combinables: rules,
        effect: policyEffect,
        target: policyTarget,
        rules: [],
        evaluation_cacheable: evaluationCacheable
      };
      policies.set(policy.id, policy);
    }

    const policySet: PolicySetWithCombinables = {
      id: policySetYaml.id,
      name: policySetYaml.name,
      description: policySetYaml.description,
      combining_algorithm: policySetYaml.combining_algorithm,
      combinables: policies,
      policies: [],
      target: formatTarget(policySetYaml.target)
    };

    accessController.updatePolicySet(policySet);
  }

  return accessController;
};

export const loadPoliciesFromDoc = async (accessController: AccessController, filepath: string): Promise<AccessController> => {
  if (_.isNil(filepath)) {
    throw new Error('No filepath specified for policies document');
  }

  if (_.isNil(accessController)) {
    throw new Error('No filepath specified for policies document');
  }

  return new Promise<AccessController>((resolve, reject) => {
    fs.exists(filepath, (exists) => {
      if (!exists) {
        reject(`Policies file ${filepath} does not exist`);
      }

      fs.readFile(filepath, (err, data) => {
        const document = yaml.safeLoad(data, 'utf8');
        loadPolicies(document, accessController);
        resolve(accessController);
      });
    });
  });
};

export interface Response {
  payload: any;
  count: number;
  status?: {
    code: number;
    message: string;
  };
}

export interface AccessResponse {
  decision: Response_Decision;
  response?: Response;
  obligation?: Obligation[];
  operation_status: {
    code: number;
    message: string;
  };
}

export interface FilterType {
  field?: string;
  operation?: 'lt' | 'lte' | 'gt' | 'gte' | 'eq' | 'in' | 'isEmpty' | 'iLike';
  value?: string;
  type?: 'string' | 'boolean' | 'number' | 'date' | 'array';
}

export interface ReadPolicyResponse extends AccessResponse {
  policy_sets?: PolicySetRQ[];
  filters?: FilterOp[];
  custom_query_args?: {
    custom_queries: any;
    custom_arguments: any;
  };
}

// Create a ids client instance
let idsClientInstance: UserServiceClient;
const getUserServiceClient = async () => {
  if (!idsClientInstance) {
    const cfg = createServiceConfig(process.cwd());
    // identity-srv client to resolve subject ID by token
    const grpcIDSConfig = cfg.get('client:user');
    const loggerCfg = cfg.get('logger');
    loggerCfg.esTransformer = (msg) => {
      msg.fields = JSON.stringify(msg.fields);
      return msg;
    };
    const logger = createLogger(loggerCfg);
    if (grpcIDSConfig) {
      const channel = createChannel(grpcIDSConfig.address);
      idsClientInstance = createClient({
        ...grpcIDSConfig,
        logger
      }, UserServiceDefinition, channel);
    }
  }
  return idsClientInstance;
};

export async function checkAccessRequest(ctx: ACSClientContext, resource: Resource[], action: AuthZAction, operation: Operation.isAllowed, useCache?: boolean): Promise<DecisionResponse>;
export async function checkAccessRequest(ctx: ACSClientContext, resource: Resource[], action: AuthZAction, operation: Operation.whatIsAllowed, useCache?: boolean): Promise<PolicySetRQResponse>;

/**
 * Perform an access request using inputs from a GQL request
 *
 * @param subject Subject information
 * @param resources resources
 * @param action The action to perform
 * @param entity The entity type to check access against
 */
/* eslint-disable prefer-arrow-functions/prefer-arrow-functions */
export async function checkAccessRequest(ctx: ACSClientContext, resource: Resource[], action: AuthZAction,
  operation: Operation): Promise<DecisionResponse | PolicySetRQResponse> {
  let subject = ctx.subject;
  // resolve subject id using findByToken api and update subject with id
  let dbSubject;
  if (subject?.token) {
    const idsClient = await getUserServiceClient();
    if (idsClient) {
      dbSubject = await idsClient.findByToken({ token: subject.token });
      if (dbSubject && dbSubject.payload && dbSubject.payload.id) {
        subject.id = dbSubject.payload.id;
      }
    }
  }

  let result: DecisionResponse | PolicySetRQResponse;
  try {
    result = await accessRequest(subject, resource, action, ctx, operation);
  } catch (err) {
    return {
      decision: Response_Decision.DENY,
      obligations: [],
      operation_status: {
        code: err.code || 500,
        message: err.details || err.message,
      }
    };
  }
  return result;
}

/**
 * reads meta data from DB and updates owner information in resource if action is UPDATE / DELETE
 * @param reaources list of resources
 * @param entity entity name
 * @param action resource action
 */
export async function createMetadata(resources: any,
  action: string, subject: Subject, service: any): Promise<any> {
  let orgOwnerAttributes = [];
  if (resources && !_.isArray(resources)) {
    resources = [resources];
  }
  const urns = service.cfg.get('authorization:urns');
  if (subject && subject.scope && (action === AuthZAction.CREATE || action === AuthZAction.MODIFY)) {
    // add user and subject scope as default owner
    orgOwnerAttributes.push(
      {
        id: urns.ownerIndicatoryEntity,
        value: urns.organization,
        attributes: [{
          id: urns.ownerInstance,
          value: subject.scope
        }]
      });
  }

  if (resources?.length > 0) {
    for (let resource of resources) {
      if (!resource.meta) {
        resource.meta = {};
      }
      if (action === AuthZAction.MODIFY || action === AuthZAction.DELETE) {
        let result = await service.readMetaData(resource.id);
        // update owner info
        if (result?.items?.length === 1) {
          let item = result.items[0].payload;
          resource.meta.owners = item.meta.owners;
        } else if (result?.items?.length === 0) {
          if (_.isEmpty(resource.id)) {
            resource.id = uuid.v4().replace(/-/g, '');
          }
          let ownerAttributes;
          if (!resource.meta.owners) {
            ownerAttributes = _.cloneDeep(orgOwnerAttributes);
          } else {
            ownerAttributes = resource.meta.owners;
          }
          if (subject && subject.id) {
            ownerAttributes.push(
              {
                id: urns.ownerIndicatoryEntity,
                value: urns.user,
                attributes: [{
                  id: urns.ownerInstance,
                  value: subject.id
                }]
              });
          }
          resource.meta.owners = ownerAttributes;
        }
      } else if (action === AuthZAction.CREATE) {
        if (_.isEmpty(resource.id)) {
          resource.id = uuid.v4().replace(/-/g, '');
        }
        let ownerAttributes;
        if (!resource.meta.owners) {
          ownerAttributes = _.cloneDeep(orgOwnerAttributes);
        } else {
          ownerAttributes = resource.meta.owners;
        }
        if (subject && subject.id) {
          ownerAttributes.push(
            {
              id: urns.ownerIndicatoryEntity,
              value: urns.user,
              attributes: [{
                id: urns.ownerInstance,
                value: subject.id
              }]
            });
        }
        resource.meta.owners = ownerAttributes;
      }
    }
  }
  return resources;
}

export const getAllValues = (obj: any, pushedValues: any): any => {
  for (let value of (<any>Object).values(obj)) {
    if (_.isArray(value)) {
      getAllValues(value, pushedValues);
    } else if (typeof value == 'string') {
      pushedValues.push(value);
    } else {
      // It is an object
      getAllValues(value, pushedValues);
    }
  }
};

const nestedAttributesEqual = (redisAttributes, userAttributes) => {
  if (!userAttributes) {
    return true;
  }
  if (redisAttributes?.length > 0 && userAttributes?.length > 0) {
    return userAttributes.every((obj) => redisAttributes.some((dbObj => dbObj.value === obj.value)));
  } else if (redisAttributes?.length != userAttributes?.length) {
    return false;
  }
};

export const compareRoleAssociations = (userRoleAssocs: RoleAssociation[], redisRoleAssocs: RoleAssociation[], logger): boolean => {
  let roleAssocsModified = false;
  if (userRoleAssocs?.length != redisRoleAssocs?.length) {
    roleAssocsModified = true;
    logger.debug('Role associations length are not equal');
  } else {
    // compare each role and its association
    if (userRoleAssocs?.length > 0 && redisRoleAssocs?.length > 0) {
      for (let userRoleAssoc of userRoleAssocs) {
        let found = false;
        for (let redisRoleAssoc of redisRoleAssocs) {
          if (redisRoleAssoc.role === userRoleAssoc.role) {
            if (redisRoleAssoc?.attributes?.length > 0) {
              for (let redisAttribute of redisRoleAssoc.attributes) {
                const redisNestedAttributes = redisAttribute.attributes;
                if (userRoleAssoc?.attributes?.length > 0) {
                  for (let userAttribute of userRoleAssoc.attributes) {
                    const userNestedAttributes = userAttribute.attributes;
                    if (userAttribute.id === redisAttribute.id &&
                      userAttribute.value === redisAttribute.value &&
                      nestedAttributesEqual(redisNestedAttributes, userNestedAttributes)) {
                      found = true;
                      break;
                    }
                  }
                }
              }
            } else {
              found = true;
              break;
            }
          }
        }
        if (!found) {
          roleAssocsModified = true;
        }
        if (roleAssocsModified) {
          logger.debug('Role associations objects are not equal');
          break;
        } else {
          logger.debug('Role assocations not changed');
        }
      }
    }
  }
  return roleAssocsModified;
};

export const flushACSCache = async (userId: string, db_index, commandTopic: Topic, logger) => {
  const payload = {
    data: {
      db_index,
      pattern: userId
    }
  };
  const eventObject = {
    name: 'flush_cache',
    payload: {}
  };
  const eventPayload = Buffer.from(JSON.stringify(payload)).toString('base64');
  eventObject.payload = {
    type_url: 'payload',
    value: eventPayload
  };
  await commandTopic.emit('flushCacheCommand', eventObject);
  logger.info('ACS flush cache command event emitted to kafka topic successfully');
};

export const updateScopedRoles = (meta, scopedRoles, urns: Map<string, string>, totalScopingEntities: string[]): Map<string, Map<string, string[]>> => {
  meta.owners.filter((owner) => owner.id === urns.get('ownerEntity') && _.find(totalScopingEntities, e => e === owner.value)).forEach(
    (owner) => {
      let ownerEntity = owner.value;
      owner.attributes.filter(((ownerInstObj) => ownerInstObj.id == urns.get('ownerInstance') && !!ownerEntity)).forEach(
        (ownerInstObj) => {
          scopedRoles.forEach((entities, role) => {
            if (entities.has(ownerEntity)) {
              const instances = entities.get(ownerEntity);
              instances.push(ownerInstObj.value);
              entities.set(ownerEntity, instances);
              scopedRoles.set(role, entities);
            }
          });
          ownerEntity = null;
        }
      );
    }
  );
  return scopedRoles;
};