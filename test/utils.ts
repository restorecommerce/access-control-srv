import * as _ from 'lodash';
import * as yaml from 'js-yaml';
import * as fs from 'fs';
import * as core from '../src/core';
import { formatTarget } from '../src/core/utils';
export { formatTarget };
import { createLogger } from '@restorecommerce/logger';
import { createServiceConfig } from '@restorecommerce/service-config';
import { Request } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/access_control';
import { Attribute } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/attribute';
import { Rule, Effect } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/rule';
import { PolicyWithCombinables, PolicySetWithCombinables } from '../src/core/interfaces';

export const cfg = createServiceConfig(process.cwd() + '/test');
export const logger = createLogger(cfg.get('logger'));

/**
 *
 * @param opts
 */
export const buildRequest = (opts: RequestOpts): Request => {

  let subjects: Attribute[] = [];
  let resources: Attribute[] = [];
  const actions: Attribute[] = [];

  subjects = subjects.concat([
    {
      id: 'urn:restorecommerce:acs:names:role',
      value: opts.subjectRole ? opts.subjectRole : 'SimpleUser',
      attributes: []
    },
    {
      id: 'urn:oasis:names:tc:xacml:1.0:subject:subject-id',
      value: opts.subjectID,
      attributes: []
    }
  ]);

  if (opts.roleScopingEntity && opts.roleScopingInstance) {
    subjects = subjects.concat([
      {
        id: 'urn:restorecommerce:acs:names:roleScopingEntity',
        value: opts.roleScopingEntity,
        attributes: [{
          id: 'urn:restorecommerce:acs:names:roleScopingInstance',
          value: opts.targetScopingInstance ? opts.targetScopingInstance : opts.roleScopingInstance,
          attributes: []
        }]
      }
    ]);
  }

  if (opts.actionType === 'urn:restorecommerce:acs:names:action:execute') {
    if (typeof opts.resourceType === 'string') {
      resources = resources.concat([
        {
          id: 'urn:restorecommerce:acs:names:operation',
          value: opts.resourceType as string,
          attributes: []
        }
      ]);
    } else {
      opts.resourceType.forEach((operationName) => {
        resources = resources.concat([
          {
            id: 'urn:restorecommerce:acs:names:operation',
            value: operationName,
            attributes: []
          }
        ]);
      });
    }
  } else {
    if (typeof opts.resourceType === 'string') {
      resources = resources.concat([
        {
          id: 'urn:restorecommerce:acs:names:model:entity',
          value: opts.resourceType as string,
          attributes: []
        },
        {
          id: 'urn:oasis:names:tc:xacml:1.0:resource:resource-id',
          value: opts.resourceID as string,
          attributes: []
        },
      ]);
      if (opts.resourceProperty && typeof opts.resourceProperty === 'string') {
        resources = resources.concat([{
          id: 'urn:restorecommerce:acs:names:model:property',
          value: opts.resourceProperty,
          attributes: []
        }]);
      } else if (opts.resourceProperty && _.isArray(opts.resourceProperty)) {
        for (let resourceProperty of opts.resourceProperty) {
          resources = resources.concat([{
            id: 'urn:restorecommerce:acs:names:model:property',
            value: resourceProperty,
            attributes: []
          }]);
        }
      }
    } else {
      for (let i = 0; i < opts.resourceType.length; i++) {
        let resourceID;
        if (opts.resourceID && opts.resourceID[i]) {
          resourceID = opts.resourceID[i];
        }
        resources = resources.concat([
          {
            id: 'urn:restorecommerce:acs:names:model:entity',
            value: opts.resourceType[i],
            attributes: []
          },
          {
            id: 'urn:oasis:names:tc:xacml:1.0:resource:resource-id',
            value: resourceID,
            attributes: []
          },
        ]);
        if (opts.resourceProperty && typeof opts.resourceProperty === 'string') {
          resources = resources.concat([{
            id: 'urn:restorecommerce:acs:names:model:property',
            value: opts.resourceProperty,
            attributes: []
          }]);
        } else if (opts.resourceProperty && _.isArray(opts.resourceProperty)) {
          for (let resourceProperty of opts.resourceProperty) {
            if (typeof resourceProperty === 'string') {
              resources = resources.concat([{
                id: 'urn:restorecommerce:acs:names:model:property',
                value: resourceProperty,
                attributes: []
              }]);
            } else if (_.isArray(resourceProperty)) {
              // TODO add only specific resource prop types related
              const entityName = opts.resourceType[i].substring(opts.resourceType[i].lastIndexOf(':') + 1);
              for (let resProp of resourceProperty) {
                if (resProp.indexOf(entityName) > -1) {
                  resources = resources.concat([{
                    id: 'urn:restorecommerce:acs:names:model:property',
                    value: resProp,
                    attributes: []
                  }]);
                }
              }
            }
          }
        }
      }
    }
  }

  actions.push({
    id: 'urn:oasis:names:tc:xacml:1.0:action:action-id',
    value: opts.actionType,
    attributes: []
  });

  let acls = [];
  if (opts.aclIndicatoryEntity && opts.aclInstances) {
    let aclInstances = [];
    opts.aclInstances.forEach(aclInstance => {
      aclInstances.push({
        id: 'urn:restorecommerce:acs:names:aclInstance',
        value: aclInstance
      });
    });
    acls = [
      {
        attributes: {
          id: 'urn:restorecommerce:acs:names:aclIndicatoryEntity',
          value: opts.aclIndicatoryEntity,
          attributes: aclInstances
        }
      }];
  } else if (opts.multipleAclIndicatoryEntity && opts.orgInstances && opts.subjectInstances) {
    let orgInstances = [], subjectInstances = [];
    opts.orgInstances.forEach(orgInstance => {
      orgInstances.push({
        id: 'urn:restorecommerce:acs:names:aclInstance',
        value: orgInstance
      });
    });
    opts.subjectInstances.forEach(subjectInstance => {
      subjectInstances.push({
        id: 'urn:restorecommerce:acs:names:aclInstance',
        value: subjectInstance
      });
    });
    acls = [
      {
        attributes: {
          id: 'urn:restorecommerce:acs:names:aclIndicatoryEntity',
          value: opts.multipleAclIndicatoryEntity[0],
          attributes: orgInstances
        }
      },
      {
        attributes: {
          id: 'urn:restorecommerce:acs:names:aclIndicatoryEntity',
          value: opts.multipleAclIndicatoryEntity[1],
          attributes: subjectInstances
        }
      }];
  }

  let ctxResources = [];

  if (typeof opts.resourceType === 'string') {
    ctxResources = [{
      id: opts.resourceID as string,
      meta: {
        created: Date.now(), modified: Date.now(),
        acls,
        owners: (opts.ownerIndicatoryEntity && opts.ownerInstance) ? [
          {
            id: 'urn:restorecommerce:acs:names:ownerIndicatoryEntity',
            value: opts.ownerIndicatoryEntity,
            attributes: [{
              id: 'urn:restorecommerce:acs:names:ownerInstance',
              value: opts.ownerInstance
            }]
          }
        ] : []
      }
    }];
  } else {
    for (let i = 0; i < opts.resourceType.length; i++) {
      let resourceID;
      if (opts.resourceID && opts.resourceID[i]) {
        resourceID = opts.resourceID[i];
      }
      ctxResources.push({
        id: resourceID,
        meta: {
          created: Date.now(), modified: Date.now(),
          acls,
          owners: (opts.ownerIndicatoryEntity && opts.ownerInstance) ? [
            {
              id: 'urn:restorecommerce:acs:names:ownerIndicatoryEntity',
              value: opts.ownerIndicatoryEntity,
              attributes: [{
                id: 'urn:restorecommerce:acs:names:ownerInstance',
                value: opts.ownerInstance[i]
              }]
            }
          ] : []
        }
      });
    }
  }

  return {
    target: {
      subjects,
      resources,
      actions
    },
    context: {
      resources: ctxResources,
      subject: {
        id: opts.subjectID,
        role_associations: opts.subjectRole && opts.roleScopingEntity && opts.roleScopingInstance ? [
          {
            role: opts.subjectRole,
            attributes: [
              {
                id: 'urn:restorecommerce:acs:names:roleScopingEntity',
                value: opts.roleScopingEntity,
                attributes: [{
                  id: 'urn:restorecommerce:acs:names:roleScopingInstance',
                  value: opts.roleScopingInstance
                }]
              }
            ]
          }
        ] : [],
        hierarchical_scopes: opts.roleScopingInstance && opts.roleScopingEntity ? [
          {
            id: 'SuperOrg1',
            role: opts.subjectRole,
            children: [
              {
                id: 'Org1',
                children: [
                  {
                    id: 'Org2',
                    children: [
                      {
                        id: 'Org3'
                      }
                    ]
                  }
                ]
              }
            ]
          }
        ] : []
      }
    }
  } as any;
};

export const marshallYamlPolicies = (yamlPolicies: any): any => {
  const policySets = [];
  const policies = [];
  const rules = [];

  for (let policySet of yamlPolicies.policy_sets) {
    const policySetObj = _.pick<any>(policySet, ['id', 'name', 'description', 'target', 'combining_algorithm']);
    policySetObj.policies = policySet.policies ? policySet.policies.map((p) => { return p.id; }) : [];
    _.set(policySetObj, 'meta', {
      owners: [],
      modified_by: ''
    });
    policySets.push(policySetObj);
    for (let policy of policySet.policies) {
      const ruleIDs = policy.rules ? policy.rules.map((p) => { return p.id; }) : [];
      const obj = _.pick<any>(policy, ['id', 'name', 'description', 'target', 'combining_algorithm', 'effect']);
      obj.rules = ruleIDs;
      _.set(obj, 'rules', ruleIDs);
      _.set(obj, 'meta', {
        owners: [],
        modified_by: ''
      });
      policies.push(obj);
      for (let rule of policy.rules) {
        rule.meta = {
          owners: [],
          modified_by: ''
        };
        rules.push(
          _.pick(rule, ['id', 'name', 'description', 'condition', 'context_query', 'target', 'effect', 'meta'])
        );
      }
    }
  }

  return {
    policySets, policies, rules
  };
};


export interface RequestOpts {
  subjectID: string;
  subjectRole?: string;
  roleScopingEntity?: string;
  roleScopingInstance?: string;
  targetScopingInstance?: string;
  actionType?: string;
  resourceID?: string | string[];
  resourceProperty?: any;
  resourceType: string | string[];
  ownerIndicatoryEntity?: string;
  ownerInstance?: string | string[];
  aclIndicatoryEntity?: string;
  aclInstances?: string[];
  multipleAclIndicatoryEntity?: string[],
  orgInstances?: string[];
  subjectInstances?: string[];
}

export const marshallProtobufAny = (object: any): any => {
  return {
    type_url: '',
    value: Buffer.from(JSON.stringify(object))
  };
};

export const marshallRequest = (request: Request): void => {
  request.context.resources = request.context.resources.map(marshallProtobufAny);
  request.context.subject = marshallProtobufAny(request.context.subject || []);
};


export const populate = (accessController: core.AccessController, filepath: string): core.AccessController => {
  const rawObject = yaml.load(fs.readFileSync(filepath));
  const policySets = rawObject.policy_sets;

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

          // const effect: core.Effect = core.Effect[core.Effect[ruleYaml.effect]];
          const effect: Effect = ruleYaml.effect;
          const context_query = ruleYaml.context_query;  // may be null
          const condition = ruleYaml.condition; // JS code; may be null
          const evaluation_cacheable = ruleYaml.evaluation_cacheable;

          const rule: Rule = {
            id: ruleID,
            name: ruleName,
            description: ruleDescription,
            target: ruleTarget,
            effect,
            context_query,
            condition,
            evaluation_cacheable
          };
          rules.set(rule.id, rule);
        }
      }

      const policyID = policyYaml.id;
      const policyName = policyYaml.name;
      const policyDescription = policyYaml.description;
      const policyCA = policyYaml.combining_algorithm;
      const policyEffect = policyYaml.effect;
      const evaluation_cacheable = policyYaml.evaluation_cacheable;
      const policyTarget = formatTarget(policyYaml.target);

      const policy: PolicyWithCombinables = {
        id: policyID,
        name: policyName,
        description: policyDescription,
        combining_algorithm: policyCA,
        combinables: rules,
        effect: policyEffect,
        target: policyTarget,
        rules: [],
        evaluation_cacheable
      };
      policies.set(policy.id, policy);
    }

    const policySet: PolicySetWithCombinables = {
      id: policySetYaml.id,
      name: policySetYaml.name,
      description: policySetYaml.description,
      combining_algorithm: policySetYaml.combining_algorithm,
      combinables: policies,
      target: formatTarget(policySetYaml.target),
      policies: []
    };

    accessController.updatePolicySet(policySet);
  }

  return accessController;
};
