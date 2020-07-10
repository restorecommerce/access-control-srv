import * as _ from 'lodash';
import * as yaml from 'js-yaml';
import * as fs from 'fs';

import * as core from '../lib/core';
import { formatTarget } from '../lib/core/utils';
export { formatTarget };

/**
 *
 * @param opts
 */
export function buildRequest(opts: RequestOpts): core.Request {

  let subject: core.Attribute[] = [];
  let resources: core.Attribute[] = [];
  const action: core.Attribute[] = [];

  subject = subject.concat([
    {
      id: 'urn:restorecommerce:acs:names:role',
      value: opts.subjectRole ? opts.subjectRole : 'SimpleUser'
    },
    {
      id: 'urn:oasis:names:tc:xacml:1.0:subject:subject-id',
      value: opts.subjectID
    }
  ]);

  if (opts.roleScopingEntity && opts.roleScopingInstance) {
    subject = subject.concat([
      {
        id: 'urn:restorecommerce:acs:names:roleScopingEntity',
        value: opts.roleScopingEntity
      },
      {
        id: 'urn:restorecommerce:acs:names:roleScopingInstance',
        value: opts.targetScopingInstance ? opts.targetScopingInstance : opts.roleScopingInstance
      }
    ]);
  }

  resources = resources.concat([
    {
      id: 'urn:restorecommerce:acs:names:model:entity',
      value: opts.resourceType
    },
    {
      id: 'urn:restorecommerce:acs:names:model:property',
      value: opts.resourceProperty
    },
    {
      id: 'urn:oasis:names:tc:xacml:1.0:resource:resource-id',
      value: opts.resourceID
    },
  ]);

  action.push({
    id: 'urn:oasis:names:tc:xacml:1.0:action:action-id',
    value: opts.actionType
  });

  return {
    target: {
      subject,
      resources,
      action
    },
    context: {
      resources: [
        {
          id: opts.resourceID,
          meta: {
            created: Date.now(), modified: Date.now(),
            owner: (opts.ownerIndicatoryEntity && opts.ownerInstance ) ? [
              {
                id: 'urn:restorecommerce:acs:names:ownerIndicatoryEntity',
                value: opts.ownerIndicatoryEntity
              }, {
                id: 'urn:restorecommerce:acs:names:ownerInstance',
                value: opts.ownerInstance
              }
            ] : []
          }
        }
      ],
      subject: {
        id: opts.subjectID,
        role_associations: opts.subjectRole && opts.roleScopingEntity && opts.roleScopingInstance ? [
          {
            role: opts.subjectRole,
            attributes: [
              {
                id: 'urn:restorecommerce:acs:names:roleScopingEntity',
                value: opts.roleScopingEntity
              },
              {
                id: 'urn:restorecommerce:acs:names:roleScopingInstance',
                value: opts.roleScopingInstance
              },
            ]
          }
        ] : [],
        hierarchical_scope: opts.roleScopingInstance && opts.roleScopingEntity ? [
          {
            id: 'SuperOrg1',
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
  };
}

export function marshallYamlPolicies(yamlPolicies: any): any {
  const policySets = [];
  const policies = [];
  const rules = [];

  for (let policySet of yamlPolicies.policy_sets) {
    const policySetObj = _.pick<any>(policySet, ['id', 'description', 'target', 'combining_algorithm']);
    policySetObj.policies = policySet.policies ? policySet.policies.map((p) => { return p.id; }) : [];
    _.set(policySetObj, 'meta', {
      owner: [],
      modified_by: ''
    });
    policySets.push(policySetObj);
    for (let policy of policySet.policies) {
      const ruleIDs = policy.rules ? policy.rules.map((p) => { return p.id; }) : [];
      const obj = _.pick<any>(policy, ['id', 'description', 'target', 'combining_algorithm', 'effect']);
      obj.rules = ruleIDs;
      _.set(obj, 'rules', ruleIDs);
      _.set(obj, 'meta', {
        owner: [],
        modified_by: ''
      });
      policies.push(obj);
      for (let rule of policy.rules) {
        rule.meta = {
          owner: [],
          modified_by: ''
        };
        rules.push(
          _.pick(rule, ['id', 'description', 'condition', 'context_query', 'target', 'effect', 'meta'])
        );
      }
    }
  }

  return {
    policySets, policies, rules
  };
}


export interface RequestOpts {
  subjectID: string;
  subjectRole?: string;
  roleScopingEntity?: string;
  roleScopingInstance?: string;
  targetScopingInstance?: string;
  actionType?: string;
  resourceID?: string;
  resourceProperty?: string;
  resourceType: string;
  ownerIndicatoryEntity?: string;
  ownerInstance?: string;
}

export function marshallProtobufAny(object: any): any {
  return {
    type_url: '',
    value: Buffer.from(JSON.stringify(object))
  };
}

// gRPC requests
export function marshallRequest(request: core.Request): void {
  request.context.resources = request.context.resources.map(marshallProtobufAny);
  request.context.subject = marshallProtobufAny(request.context.subject || []);
}

export function populate(accessController: core.AccessController, filepath: string): core.AccessController {
  const rawObject = yaml.safeLoad(fs.readFileSync(filepath));
  const policySets = rawObject.policy_sets;

  for (let policySetYaml of policySets) {

    let policies = new Map<string, core.Policy>();
    for (let policyYaml of policySetYaml.policies) {

      let rules = new Map<string, core.Rule>();
      if (policyYaml.rules) {
        for (let ruleYaml of policyYaml.rules) {
          const ruleID = ruleYaml.id;
          const ruleName = ruleYaml.name;
          const ruleDescription: string = ruleYaml.description;
          const ruleTarget = formatTarget(ruleYaml.target);

          // const effect: core.Effect = core.Effect[core.Effect[ruleYaml.effect]];
          const effect: core.Effect = ruleYaml.effect;
          const contextQuery = ruleYaml.context_query;  // may be null
          const condition = ruleYaml.condition; // JS code; may be null

          const rule: core.Rule = {
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

      const policy: core.Policy = {
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

    const policySet: core.PolicySet = {
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
}
