import * as _ from 'lodash-es';
import fs from 'node:fs';
import yaml from 'js-yaml';
import { AccessController } from './accessController.js';
import {
  AuthZAction,
  accessRequest,
  PolicySetRQ,
  DecisionResponse,
  Operation,
  PolicySetRQResponse,
  Obligation,
  ACSClientContext,
  ACSResource as Resource
} from '@restorecommerce/acs-client';
import { Subject } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/auth.js';
import { Response_Decision } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/access_control.js';
import { createServiceConfig } from '@restorecommerce/service-config';
import { createLogger, Logger } from '@restorecommerce/logger';
import { createClient, createChannel } from '@restorecommerce/grpc-client';
import { FilterOp } from '@restorecommerce/resource-base-interface/lib/core/interfaces.js';
import { Request } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/access_control.js';
import { Rule, Target, Effect } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/rule.js';
import {
  UserServiceDefinition,
  UserServiceClient
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/user.js';
import { PolicySetWithCombinables, PolicyWithCombinables } from './interfaces.js';
import { RoleAssociation } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/auth.js';
import { Topic } from '@restorecommerce/kafka-client';
import { Attribute } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/attribute.js';
import { randomUUID } from 'node:crypto';


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
  const evalResult = eval(condition);
  if (typeof evalResult === 'function') {
    return evalResult(request);
  } else {
    return evalResult;
  }
};

const loadPolicies = (document: any, accessController: AccessController): AccessController => {
  const policySets = document?.policy_sets ? document.policy_sets : [];

  for (const policySetYaml of policySets) {

    const policies = new Map<string, PolicyWithCombinables>();
    for (const policyYaml of policySetYaml.policies) {

      const rules = new Map<string, Rule>();
      if (policyYaml.rules) {
        for (const ruleYaml of policyYaml.rules) {
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
  if (!filepath?.length) {
    throw new Error('No filepath specified for policies document');
  }

  if (!accessController) {
    throw new Error('No filepath specified for policies document');
  }

  return new Promise<AccessController>((resolve, reject) => {
    fs.readFile(filepath, (err, data) => {
      if (err?.code === 'EEXIST') {
        reject(new Error(`Policies file ${filepath} does not exist`));
      }
      else if (err) {
        reject(err);
      }
      else {
        const document = yaml.loadAll(data.toString());
        loadPolicies(document, accessController);
        resolve(accessController);
      }
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
const cfg = createServiceConfig(process.cwd());
const getUserServiceClient = async () => {
  if (!idsClientInstance) {
    // identity-srv client to resolve subject ID by token
    const grpcIDSConfig = cfg.get('client:user');
    const loggerCfg = cfg.get('logger');
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
export async function checkAccessRequest(ctx: ACSClientContext, resource: Resource[], action: AuthZAction,
  operation: Operation): Promise<DecisionResponse | PolicySetRQResponse> {
  const subject = ctx.subject as Subject;
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
    result = await accessRequest(
      subject,
      resource,
      action,
      ctx,
      {
        operation,
        roleScopingEntityURN: cfg?.get('authorization:urns:roleScopingEntityURN')
      } as any
    );
  } catch (err: any) {
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
  const orgOwnerAttributes = [];
  if (resources && !Array.isArray(resources)) {
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
    for (const resource of resources) {
      if (!resource.meta) {
        resource.meta = {};
      }
      if (action === AuthZAction.MODIFY || action === AuthZAction.DELETE) {
        const result = await service.readMetaData(resource.id);
        // update owner info
        if (result?.items?.length === 1) {
          const item = result.items[0].payload;
          resource.meta.owners = item.meta.owners;
        } else if (result?.items?.length === 0) {
          if (!resource?.id?.length) {
            resource.id = randomUUID().replace(/-/g, '');
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
        if (!resource?.id?.length) {
          resource.id = randomUUID().replace(/-/g, '');
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
  for (const value of (<any>Object).values(obj)) {
    if (Array.isArray(value)) {
      getAllValues(value, pushedValues);
    } else if (typeof value == 'string') {
      pushedValues.push(value);
    } else {
      // It is an object
      getAllValues(value, pushedValues);
    }
  }
};

const nestedAttributesEqual = (redisAttributes: Attribute[], userAttributes: Attribute[]) => {
  if (!userAttributes) {
    return true;
  }
  if (redisAttributes?.length > 0 && userAttributes?.length > 0) {
    return userAttributes.every((obj) => redisAttributes.some((dbObj) => dbObj.value === obj.value));
  } else if (redisAttributes?.length != userAttributes?.length) {
    return false;
  }
};

export const compareRoleAssociations = (userRoleAssocs: RoleAssociation[], redisRoleAssocs: RoleAssociation[], logger?: Logger): boolean => {
  let roleAssocsModified = false;
  if (userRoleAssocs?.length != redisRoleAssocs?.length) {
    roleAssocsModified = true;
    logger?.debug('Role associations length are not equal');
  } else {
    // compare each role and its association
    if (userRoleAssocs?.length > 0 && redisRoleAssocs?.length > 0) {
      for (const userRoleAssoc of userRoleAssocs) {
        let found = false;
        for (const redisRoleAssoc of redisRoleAssocs) {
          if (redisRoleAssoc.role === userRoleAssoc.role) {
            if (redisRoleAssoc?.attributes?.length > 0) {
              for (const redisAttribute of redisRoleAssoc.attributes) {
                const redisNestedAttributes = redisAttribute.attributes;
                if (userRoleAssoc?.attributes?.length > 0) {
                  for (const userAttribute of userRoleAssoc.attributes) {
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
          logger?.debug('Role associations objects are not equal');
          break;
        } else {
          logger?.debug('Role assocations not changed');
        }
      }
    }
  }
  return roleAssocsModified;
};

export const flushACSCache = async (userId: string, db_index: number, commandTopic: Topic, logger?: Logger) => {
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
  const eventPayload = Buffer.from(JSON.stringify(payload));
  eventObject.payload = {
    type_url: 'payload',
    value: eventPayload
  };
  await commandTopic.emit('flushCacheCommand', eventObject);
  logger?.info('ACS flush cache command event emitted to kafka topic successfully');
};
