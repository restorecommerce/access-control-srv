import yaml from 'js-yaml';
import fs from 'node:fs';
import { AccessController } from '../src/core/accessController.js';
import { formatTarget } from '../src/core/utils.js';
export { formatTarget };
import { createLogger } from '@restorecommerce/logger';
import { createServiceConfig } from '@restorecommerce/service-config';
import { Request } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/access_control.js';
import { Attribute } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/attribute.js';
import { Rule, Effect } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/rule.js';
import { PolicyWithCombinables, PolicySetWithCombinables } from '../src/core/interfaces.js';
import { PolicySet } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/policy_set.js';
import { Policy } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/policy.js';
import { Resource } from '@restorecommerce/resource-base-interface/lib/core/interfaces.js';
import { urns } from '@restorecommerce/acs-client';

export const cfg = createServiceConfig(process.cwd());
export const logger = createLogger(cfg.get('logger'));

/**
 *
 * @param opts
 */
export const buildRequest = (opts: RequestOpts): Request => {
  const resources: Attribute[] = [];
  const actions: Attribute[] = [];
  const subjects: Attribute[] = [
    {
      id: urns.role,
      value: opts.subjectRole ? opts.subjectRole : 'SimpleUser',
      attributes: []
    },
    {
      id: urns.subjectID,
      value: opts.subjectID,
      attributes: []
    }
  ];

  if (opts.actionType === urns.execute) {
    if (typeof opts.resourceType === 'string') {
      resources.push({
        id: urns.operation,
        value: opts.resourceType,
        attributes: []
      });
    } else {
      opts.resourceType.forEach((operationName) => {
        resources.push({
          id: urns.operation,
          value: operationName,
          attributes: []
        });
      });
    }
  } else {
    if (typeof opts.resourceType === 'string') {
      resources.push(...[
        {
          id: urns.entity,
          value: opts.resourceType as string,
          attributes: []
        },
        {
          id: urns.resourceID,
          value: opts.resourceID as string,
          attributes: []
        },
      ]);
      if (opts.resourceProperty && typeof opts.resourceProperty === 'string') {
        resources.push({
          id: urns.property,
          value: opts.resourceProperty,
          attributes: []
        });
      } else if (opts.resourceProperty && Array.isArray(opts.resourceProperty)) {
        for (let resourceProperty of opts.resourceProperty) {
          resources.push({
            id: urns.property,
            value: resourceProperty,
            attributes: []
          });
        }
      }
    } else {
      for (let i = 0; i < opts.resourceType.length; i++) {
        let resourceID;
        if (opts.resourceID && opts.resourceID[i]) {
          resourceID = opts.resourceID[i];
        }
        resources.push(...[
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
          resources.push({
            id: 'urn:restorecommerce:acs:names:model:property',
            value: opts.resourceProperty,
            attributes: []
          });
        } else if (opts.resourceProperty && Array.isArray(opts.resourceProperty)) {
          for (let resourceProperty of opts.resourceProperty) {
            if (typeof resourceProperty === 'string') {
              resources.push({
                id: 'urn:restorecommerce:acs:names:model:property',
                value: resourceProperty,
                attributes: []
              });
            } else if (Array.isArray(resourceProperty)) {
              // TODO add only specific resource prop types related
              const entityName = opts.resourceType[i].substring(opts.resourceType[i].lastIndexOf(':') + 1);
              for (let resProp of resourceProperty) {
                if (resProp.includes(entityName)) {
                  resources.push({
                    id: 'urn:restorecommerce:acs:names:model:property',
                    value: resProp,
                    attributes: []
                  });
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

  let acls = new Array<Attribute>();
  if (opts.aclIndicatoryEntity && opts.aclInstances) {
    const aclInstances: Attribute[] = opts.aclInstances.map(
      aclInstance => ({
        id: 'urn:restorecommerce:acs:names:aclInstance',
        value: aclInstance
      })
    );
    acls = [
      {
        id: urns.aclIndicatoryEntity,
        value: opts.aclIndicatoryEntity,
        attributes: aclInstances
      }
    ];
  } else if (opts.multipleAclIndicatoryEntity && opts.orgInstances && opts.subjectInstances) {
    const orgInstances: Attribute[] = opts.orgInstances.map(
      orgInstance => ({
        id: urns.aclInstance,
        value: orgInstance
      })
    );
    const subjectInstances: Attribute[] = opts.subjectInstances.map(
      subjectInstance => ({
        id: urns.aclInstance,
        value: subjectInstance
      })
    );
    acls = [
      {
        id: urns.aclIndicatoryEntity,
        value: opts.multipleAclIndicatoryEntity[0],
        attributes: orgInstances
      },
      {
        id: urns.aclIndicatoryEntity,
        value: opts.multipleAclIndicatoryEntity[1],
        attributes: subjectInstances
      }
    ];
  }

  let ctxResources = new Array<Resource>();

  if (typeof opts.resourceType === 'string') {
    ctxResources = [{
      id: opts.resourceID as string,
      meta: {
        created: new Date, modified: new Date,
        acls,
        owners: (opts.ownerIndicatoryEntity && !Array.isArray(opts.ownerInstance)) ? [
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
  } else if (Array.isArray(opts.resourceType)) {
    for (let i = 0; i < opts.resourceType.length; i++) {
      let resourceID;
      if (opts.resourceID && opts.resourceID[i]) {
        resourceID = opts.resourceID[i];
      }
      ctxResources.push({
        id: resourceID,
        meta: {
          created: new Date(),
          modified: new Date(),
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
  const policySets = new Array<PolicySet>();
  const policies = new Array<Policy>();
  const rules = new Array<Rule>();

  for (let policySet of yamlPolicies.policy_sets) {
    const ps = PolicySet.fromPartial(policySet);
    ps.policies = policySet.policies ? policySet.policies.map((ps: PolicySet) => { return ps.id; }) : [];
    policySets.push(ps);
    for (let policy of policySet.policies) {
      const ruleIDs = policy.rules ? policy.rules.map((p: Policy) => { return p.id; }) : [];
      const p = Policy.fromPartial(policy)
      p.rules = ruleIDs;
      policies.push(p);
      for (let rule of policy.rules) {
        rules.push(
          Rule.fromPartial(rule)
        );
      }
    }
  }

  return {
    policySets,
    policies,
    rules,
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
  request.context ??= {};
  request.context.resources = request.context?.resources?.map(marshallProtobufAny);
  request.context.subject = marshallProtobufAny(request?.context?.subject ?? []);
};


export const populate = (accessController: AccessController, filepath: string): AccessController => {
  const rawObject = yaml.load(fs.readFileSync(filepath).toString()) as any;
  const policySets = rawObject.policy_sets;

  for (let policySetYaml of policySets) {

    let policies = new Map<string, PolicyWithCombinables>();
    for (let policyYaml of policySetYaml.policies) {

      let rules = new Map<string, Rule>();
      if (policyYaml.rules) {
        for (let ruleYaml of policyYaml.rules) {
          const rule = Rule.fromPartial(ruleYaml);
          rule.target = formatTarget(ruleYaml.target);
          rules.set(rule.id!, rule);
        }
      }

      const policy: PolicyWithCombinables = Policy.fromPartial(policyYaml);
      policy.combinables = rules;
      policy.target = formatTarget(policyYaml.target);
      policies.set(policy.id!, policy);
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
