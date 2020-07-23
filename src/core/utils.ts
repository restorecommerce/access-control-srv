import * as _ from 'lodash';
import * as fs from 'fs';
import * as yaml from 'js-yaml';
import { AccessController } from './accessController';
import * as interfaces from './interfaces';
import { RedisClient } from 'redis';
import { Subject, AuthZAction, Decision, accessRequest, PolicySetRQ } from '@restorecommerce/acs-client';

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
}

export interface FilterType {
  field?: string;
  operation?: 'lt' | 'lte' | 'gt' | 'gte' | 'eq' | 'in' | 'isEmpty' | 'iLike';
  value?: string;
  type?: 'string' | 'boolean' | 'number' | 'date' | 'array';
}

export interface ReadPolicyResponse extends AccessResponse {
  policySet?: PolicySetRQ;
  filter?: FilterType[];
  custom_query_args?: {
    custom_queries: any;
    custom_arguments: any;
  };
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
export async function checkAccessRequest(subject: Subject, resources: any, action: AuthZAction,
  entity: string, service: any, resourceNameSpace?: string): Promise<AccessResponse | ReadPolicyResponse> {
  let authZ = service.authZ;
  let data = _.cloneDeep(resources);
  if (!_.isArray(resources) && action != AuthZAction.READ) {
    data = [resources];
  } else if (action === AuthZAction.READ) {
    data.args = resources;
    data.entity = entity;
  }

  let result: Decision | PolicySetRQ;
  try {
    result = await accessRequest(subject, data, action, authZ, entity, resourceNameSpace);
  } catch (err) {
    return {
      decision: Decision.DENY,
      response: {
        payload: undefined,
        count: 0,
        status: {
          code: err.code || 500,
          message: err.details || err.message,
        }
      }
    };
  }
  if (typeof result === 'string') {
    return {
      decision: result
    };
  }
  let custom_queries = data.args.custom_queries;
  let custom_arguments = data.args.custom_arguments;
  return {
    decision: Decision.PERMIT,
    policySet: result,
    filter: data.args.filter,
    custom_query_args: { custom_queries, custom_arguments }
  };
}

export const getSubjectFromRedis = async (call: any, redisClient: RedisClient) => {
  let subject = call.request.subject;
  if (!subject) {
    subject = {};
  }
  let api_key = call.request.api_key;
  if (subject && subject.id && _.isEmpty(subject.hierarchical_scopes)) {
    let redisKey = `cache:${subject.id}:subject`;
    // update ctx with HR scope from redis
    subject = await new Promise((resolve, reject) => {
      redisClient.get(redisKey, async (err, response) => {
        if (!err && response) {
          // update user HR scope and role_associations from redis
          const redisResp = JSON.parse(response);
          subject.role_associations = redisResp.role_associations;
          subject.hierarchical_scopes = redisResp.hierarchical_scopes;
          resolve(subject);
        }
        // when not set in redis
        if (err || (!err && !response)) {
          resolve(subject);
          return subject;
        }
      });
    });
  } else if (api_key) {
    subject = { api_key };
  }
  return subject;
};

/**
 * reads meta data from DB and updates owner information in resource if action is UPDATE / DELETE
 * @param reaources list of resources
 * @param entity entity name
 * @param action resource action
 */
export async function createMetadata(resources: any,
  action: string, subject: Subject, service: any, cb: any): Promise<any> {
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
          let item = result.items[0];
          resource.meta.owner = item.meta.owner;
        } else if (result.items.length === 0 && !resource.meta.owner) {
          let ownerAttributes = _.cloneDeep(orgOwnerAttributes);
          ownerAttributes.push(
            {
              id: urns.ownerIndicatoryEntity,
              value: urns.user
            },
            {
              id: urns.ownerInstance,
              value: resource.id
            });
          resource.meta.owner = ownerAttributes;
        }
      } else if (action === AuthZAction.CREATE && !resource.meta.owner) {
        let ownerAttributes = _.cloneDeep(orgOwnerAttributes);
        ownerAttributes.push(
          {
            id: urns.ownerIndicatoryEntity,
            value: urns.user
          },
          {
            id: urns.ownerInstance,
            value: resource.id
          });
        resource.meta.owner = ownerAttributes;
      }
    }
  }
  return resources;
}
