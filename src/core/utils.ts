import * as _ from 'lodash';
import * as fs from 'fs';
import * as yaml from 'js-yaml';
import { AccessController } from './accessController';
import * as interfaces from './interfaces';
import { Subject, AuthZAction, Decision, accessRequest, PolicySetRQ, DecisionResponse, Operation, PolicySetRQResponse } from '@restorecommerce/acs-client';
import { createServiceConfig } from '@restorecommerce/service-config';
import { createLogger } from '@restorecommerce/logger';
import { GrpcClient } from '@restorecommerce/grpc-client';
import { FilterOp } from '@restorecommerce/resource-base-interface/lib/core/interfaces';
import * as uuid from 'uuid';


export const formatTarget = (target: any): interfaces.Target => {
  if (!target) {
    return null;
  }

  return {
    subject: target.subject ? target.subject : [],
    resources: target.resources ? target.resources : [],
    action: target.action ? target.action : []
  };
};

const loadPolicies = (document: any, accessController: AccessController): AccessController => {
  const policySets = document.policy_sets;

  for (let policySetYaml of policySets) {

    let policies = new Map<string, interfaces.Policy>();
    for (let policyYaml of policySetYaml.policies) {

      let rules = new Map<string, interfaces.Rule>();
      if (policyYaml.rules) {
        for (let ruleYaml of policyYaml.rules) {
          const ruleID = ruleYaml.id;
          const ruleName = ruleYaml.name;
          const ruleDescription: string = ruleYaml.description;
          const ruleTarget = formatTarget(ruleYaml.target);

          const effect: interfaces.Effect = ruleYaml.effect;
          const contextQuery = ruleYaml.context_query;  // may be null
          const condition = ruleYaml.condition; // JS code; may be null

          const rule: interfaces.Rule = {
            id: ruleID,
            name: ruleName,
            description: ruleDescription,
            target: ruleTarget,
            effect,
            contextQuery,
            condition
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

      const policy: interfaces.Policy = {
        id: policyID,
        name: policyName,
        description: policyDescription,
        combiningAlgorithm: policyCA,
        combinables: rules,
        effect: policyEffect,
        target: policyTarget
      };
      policies.set(policy.id, policy);
    }

    const policySet: interfaces.PolicySet = {
      id: policySetYaml.id,
      name: policySetYaml.name,
      description: policySetYaml.description,
      combiningAlgorithm: policySetYaml.combining_algorithm,
      combinables: policies,
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
  decision: Decision;
  response?: Response;
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
let idsClientInstance;
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
      const idsClient = new GrpcClient(grpcIDSConfig, logger);
      idsClientInstance = idsClient.user;
    }
  }
  return idsClientInstance;
};

export interface Resource {
  resource: string;
  id?: string | string[]; // for what is allowed operation id is not mandatory
  property?: string[];
}

export interface Attribute {
  id: string;
  value: string;
  attribute: Attribute[];
}

export interface CtxResource {
  id: string;
  meta: {
    created?: number;
    modified?: number;
    modified_by?: string;
    owner: Attribute[]; // id and owner is mandatory in ctx resource other attributes are optional
  };
  [key: string]: any;
}

export interface GQLClientContext {
  // if subject is missing by default it will be treated as unauthenticated subject
  subject?: Subject;
  resources?: CtxResource[];
}

/**
 * Perform an access request using inputs from a GQL request
 *
 * @param subject Subject information
 * @param resources resources
 * @param action The action to perform
 * @param entity The entity type to check access against
 */
/* eslint-disable prefer-arrow-functions/prefer-arrow-functions */
export async function checkAccessRequest(ctx: GQLClientContext, resource: Resource[], action: AuthZAction,
  operation: Operation): Promise<DecisionResponse | ReadPolicyResponse> {
  let subject = ctx.subject;
  // resolve subject id using findByToken api and update subject with id
  let dbSubject;
  if (subject && subject.token) {
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
      decision: Decision.DENY,
      obligation: [],
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
        value: urns.organization
      },
      {
        id: urns.ownerInstance,
        value: subject.scope
      });
  }

  if (resources) {
    for (let resource of resources) {
      if (!resource.meta) {
        resource.meta = {};
      }
      if (action === AuthZAction.MODIFY || action === AuthZAction.DELETE) {
        let result = await service.readMetaData(resource.id);
        // update owner info
        if (result.items.length === 1) {
          let item = result.items[0].payload;
          resource.meta.owner = item.meta.owner;
        } else if (result.items.length === 0) {
          if (_.isEmpty(resource.id)) {
            resource.id = uuid.v4().replace(/-/g, '');
          }
          let ownerAttributes;
          if (!resource.meta.owner) {
            ownerAttributes = _.cloneDeep(orgOwnerAttributes);
          } else {
            ownerAttributes = resource.meta.owner;
          }
          if (subject && subject.id) {
            ownerAttributes.push(
              {
                id: urns.ownerIndicatoryEntity,
                value: urns.user
              },
              {
                id: urns.ownerInstance,
                value: subject.id
              });
          }
          resource.meta.owner = ownerAttributes;
        }
      } else if (action === AuthZAction.CREATE) {
        if (_.isEmpty(resource.id)) {
          resource.id = uuid.v4().replace(/-/g, '');
        }
        let ownerAttributes;
        if (!resource.meta.owner) {
          ownerAttributes = _.cloneDeep(orgOwnerAttributes);
        } else {
          ownerAttributes = resource.meta.owner;
        }
        if (subject && subject.id) {
          ownerAttributes.push(
            {
              id: urns.ownerIndicatoryEntity,
              value: urns.user
            },
            {
              id: urns.ownerInstance,
              value: subject.id
            });
        }
        resource.meta.owner = ownerAttributes;
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