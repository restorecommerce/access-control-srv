import {} from 'mocha';
import should from 'should';
import { Worker } from '../src/worker.js';
import * as testUtils from './utils.js';
import yaml from 'js-yaml';
import fs from 'node:fs';
import { updateConfig } from '@restorecommerce/acs-client';
import { createChannel, createClient } from '@restorecommerce/grpc-client';
import { RuleServiceDefinition, RuleServiceClient } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/rule.js';
import { PolicyServiceDefinition, PolicyServiceClient } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/policy.js';
import { PolicySetServiceDefinition, PolicySetServiceClient } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/policy_set.js';
import { AccessControlServiceDefinition, AccessControlServiceClient, Response_Decision } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/access_control.js';
import { PolicySetWithCombinables, PolicyWithCombinables } from '../src/core/interfaces.js';
import { cfg, logger } from './utils.js';

let worker: Worker;
let ruleService: RuleServiceClient, policyService: PolicyServiceClient, policySetService: PolicySetServiceClient;
let accessControlService: AccessControlServiceClient;
let rules, policies, policySets;

const setupService = async (): Promise<void> => {
  worker = new Worker();
  await worker.start(cfg, logger);

  const policySetCfg = cfg.get('client:policy_set');
  policySetService = createClient({
    ...policySetCfg,
    logger
  }, PolicySetServiceDefinition, createChannel(policySetCfg.address));

  const policyCfg = cfg.get('client:policy');
  policyService = createClient({
    ...policyCfg,
    logger
  }, PolicyServiceDefinition, createChannel(policyCfg.address));

  const ruleCfg = cfg.get('client:rule');
  ruleService = createClient({
    ...ruleCfg,
    logger
  }, RuleServiceDefinition, createChannel(ruleCfg.address));
};

const truncate = async (): Promise<void> => {
  await policySetService.delete({
    collection: true
  });
  await policyService.delete({
    collection: true
  });
  await ruleService.delete({
    collection: true
  });
};

const load = async (policiesFile: string): Promise<void> => {
  // load from fixtures
  const yamlPolicies = yaml.load(fs.readFileSync(policiesFile).toString());
  const marshalled = testUtils.marshallYamlPolicies(yamlPolicies);

  rules = marshalled.rules;
  policies = marshalled.policies;
  policySets = marshalled.policySets;

  const acsCfg = cfg.get('client:acs-srv');
  accessControlService = createClient({
    ...acsCfg,
    logger
  }, AccessControlServiceDefinition, createChannel(acsCfg.address));
};

const create = async (policiesFile: string): Promise<void> => {
  await load(policiesFile);
  await policySetService.create({
    items: policySets
  });
  await policyService.create({
    items: policies
  });
  await ruleService.create({
    items: rules
  });
};

describe('testing microservice', () => {
  describe('testing resource ownership with ACS disabled', () => {
    before(async () => {
      await setupService();
      await load('./test/fixtures/conditions.yml');
      // disable authorization
      cfg.set('authorization:enabled', false);
      cfg.set('authorization:enforce', false);
      updateConfig(cfg);
    });
    after(async () => {
      await worker.stop();
    });
    describe('testing create() operations', () => {
      it('it should insert policy sets', async () => {
        const result = await policySetService.create({
          items: policySets
        });
        should.exist(result);
        should.exist(result.items);
        result.items!.should.be.length(policySets.length);
        result.operation_status!.code!.should.equal(200);
        result.operation_status!.message!.should.equal('success');
      });

      it('should insert policies', async () => {
        const result = await policyService.create({
          items: policies
        });
        should.exist(result);
        should.exist(result.items);
        result.items!.should.be.length(policies!.length);
        result.operation_status!.code!.should.equal(200);
        result.operation_status!.message!.should.equal('success');
      });

      it('should insert rules', async () => {
        const result = await ruleService.create({
          items: rules
        });
        should.exist(result);
        should.exist(result.items);
        result.items!.should.be.length(rules.length);
        result.operation_status!.code!.should.equal(200);
        result.operation_status!.message!.should.equal('success');
      });

      it('should update in-memory policies when creating resources', async () => {
        const accessController = worker.accessController;
        should.exist(accessController.policySets);
        accessController.policySets.should.have.size(1);

        // checking policies
        const policySet: [string, PolicySetWithCombinables] = accessController.policySets.entries().next().value;
        should.exist(policySet[1]!.combinables);
        policySet[1]!.combinables!.should.have.size(1);

        // checking policy rules
        const policy: [string, PolicyWithCombinables] = policySet[1]!.combinables!.entries().next().value;
        should.exist(policy[1]!.combinables);
        policy[1]!.combinables!.should.have.size(3);
      });
    });

    describe('testing update() operations', () => {
      it('should update policy set info', async () => {
        // modifying policy set resource:
        //   - changing name
        //   - appending a new policy ID
        const result = await policySetService.update({
          items: [
            {
              id: 'policySetA',
              name: 'Policy set A v2',
              policies: [
                'policyA', 'policyB'
              ],
              meta: {
                owners: [],
                modified_by: ''
              }
            },
          ]
        }, {});

        should.exist(result);
        should.exist(result.items);
        result.items!.should.have.length(1);
        result.operation_status!.code!.should.equal(200);
        result.operation_status!.message!.should.equal('success');

        const updatedPS = result.items![0]!.payload;
        should.exist(updatedPS!.name);
        should.exist(updatedPS!.policies);
        updatedPS!.name!.should.equal('Policy set A v2');

        updatedPS!.policies!.should.have.length(2);
        should.exist(updatedPS!.policies![0]);
        updatedPS!.policies![0]!.should.equal('policyA');
        updatedPS!.policies![1]!.should.equal('policyB');
      });
      // TODO ADD READ tests
      // update operations are not stable due to
      // Protocol Buffers' default value behaviour, which overrides DB values
      // it('should update in-memory policy info upon update', async () => {

      // });

      // it('should update policies relation with policy sets info upon update', () => {

      // });

      // it('should update in-memory rules info upon update', async () => {

      // });

      // it('should update rules relation with policies info upon update', () => {

      // });
    });

    describe('testing delete() operations', () => {

      it('should delete rules', async () => {
        const deleteResponse = await ruleService.delete({
          ids: rules.map((r) => { return r.id; })
        });
        const result = await ruleService.read({});
        should.exist(result);
        should.not.exist(result.items);
        result.operation_status!.code!.should.equal(200);
        result.operation_status!.message!.should.equal('success');
      });

      it('should update in-memory policies by removing rules', () => {
        const accessController = worker.accessController;

        for (let [, policySet] of accessController.policySets) {
          for (let [, policy] of policySet.combinables!) {
            should.exist(policy.combinables);
            policy.combinables!.should.have.size(0);
          }
        }
      });

      it('should delete policies', async () => {
        await policyService.delete({
          ids: policies!.map((p) => { return p.id; })
        });
        const result = await policyService.read({});
        should.exist(result);
        should.not.exist(result.items);
        result.operation_status!.code!.should.equal(200);
        result.operation_status!.message!.should.equal('success');
      });

      it('should update in-memory policy sets by removing policies', () => {
        const accessController = worker.accessController;

        for (let [, policySet] of accessController.policySets) {
          should.exist(policySet.combinables);
          policySet.combinables!.should.have.size(0);
        }
      });

      it('should delete policy sets', async () => {
        await policySetService.delete({
          ids: policySets.map((p) => { return p.id; })
        });
        const result = await policySetService.read({});
        should.exist(result);
        should.not.exist(result.items);
        result.operation_status!.code!.should.equal(200);
        result.operation_status!.message!.should.equal('success');
      });

      it('should update in-memory info, which should be empty', () => {
        const accessController = worker.accessController;

        should.exist(accessController.policySets);
        accessController.policySets.should.have.size(0);
      });
    });
  });
  describe('testing access control', () => {
    before(async () => {
      await setupService();
    });
    after(async () => {
      await worker.stop();
    });
    describe('isAllowed()', () => {
      before(async () => {
        await create('./test/fixtures/conditions.yml');
      });
      after(async function (): Promise<void> {
        this.timeout(5000);
        await truncate();
      });
      it('should PERMIT', async () => {
        const accessRequest = testUtils.buildRequest({
          subjectID: 'Alice',
          subjectRole: 'SimpleUser',
          roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          roleScopingInstance: 'Org1',
          resourceType: 'urn:restorecommerce:acs:model:user.User',
          resourceProperty: 'urn:restorecommerce:acs:model:user.User#name',
          resourceID: 'Bob',
          actionType: 'urn:restorecommerce:acs:names:action:read',
        });
        testUtils.marshallRequest(accessRequest);

        const result = await accessControlService.isAllowed(accessRequest);
        should.exist(result);
        should.exist(result.decision);
        result.decision!.should.equal(Response_Decision.PERMIT);
        result.operation_status!.code!.should.equal(200);
        result.operation_status!.message!.should.equal('success');
      });

      it('should return DENY', async () => {
        const accessRequest = testUtils.buildRequest({
          subjectID: 'Alice',
          subjectRole: 'SimpleUser',
          roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          roleScopingInstance: 'Org1',
          resourceType: 'urn:restorecommerce:acs:model:user.User',
          resourceProperty: 'urn:restorecommerce:acs:model:user.User#name',
          resourceID: 'Bob',
          actionType: 'urn:restorecommerce:acs:names:action:modify'
        });
        testUtils.marshallRequest(accessRequest);

        const result = await accessControlService.isAllowed(accessRequest);
        should.exist(result);
        should.exist(result.decision);
        result.decision!.should.equal(Response_Decision.DENY);
        result.operation_status!.code!.should.equal(200);
        result.operation_status!.message!.should.equal('success');
      });

      it('should DENY due to invalid context', async () => {
        const accessRequest = testUtils.buildRequest({
          subjectID: 'Alice',
          subjectRole: 'SimpleUser',
          roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          roleScopingInstance: 'Org1',
          resourceType: 'urn:restorecommerce:acs:model:user.User',
          resourceProperty: 'urn:restorecommerce:acs:model:user.User#name',
          resourceID: 'Alice',
          actionType: 'urn:restorecommerce:acs:names:action:modify',
        });
        accessRequest.context = undefined;

        const result = await accessControlService.isAllowed(accessRequest);
        should.exist(result);
        should.exist(result.decision);
        result.decision!.should.equal(Response_Decision.DENY);
        result.operation_status!.code!.should.equal(200);
        result.operation_status!.message!.should.equal('success');
      });

      it('should return INDETERMINATE', async () => {
        const accessRequest = testUtils.buildRequest({
          subjectID: 'Alice',
          subjectRole: 'SimpleUser',
          roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          roleScopingInstance: 'Org1',
          resourceType: 'urn:restorecommerce:acs:model:unknown.Unknown',
          resourceProperty: 'urn:restorecommerce:acs:model:unknown.Unknown#random',
          resourceID: 'UnknownID',
          actionType: 'urn:restorecommerce:acs:names:action:read',
        });
        testUtils.marshallRequest(accessRequest);

        const result = await accessControlService.isAllowed(accessRequest);
        should.exist(result);
        should.exist(result.decision);
        result.decision!.should.equal(Response_Decision.INDETERMINATE);
        result.operation_status!.code!.should.equal(200);
        result.operation_status!.message!.should.equal('success');
      });
    });
    describe('testing whatIsAllowed', () => {
      before(async () => {
        await create('./test/fixtures/roleScopes.yml');
      });
      after(async () => {
        await truncate();
      });
      it('should return filtered rules for Location resource', async (): Promise<void> => {
        const accessRequest = testUtils.buildRequest({
          subjectID: 'Alice',
          subjectRole: 'SimpleUser',
          resourceType: 'urn:restorecommerce:acs:model:location.Location',
          roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          roleScopingInstance: 'SuperOrg1',
          actionType: 'urn:restorecommerce:acs:names:action:read',
        });
        testUtils.marshallRequest(accessRequest);
        const result = await accessControlService.whatIsAllowed(accessRequest);
        should.exist(result);
        should.exist(result.policy_sets);
        result.policy_sets!.should.be.length(1);

        should.exist(result.policy_sets![0]!.policies);
        result.policy_sets![0]!.policies!.should.be.length(1);
        should.exist(result.policy_sets![0]!.policies![0]!.rules);
        result.policy_sets![0]!.policies![0]!.rules!.should.have.length(2);

        const rule = result.policy_sets![0]!.policies![0]!.rules![0];
        should.exist(rule.target);
        should.exist(rule!.target!.subjects);
        rule!.target!.subjects!.should.have.length(2);
        rule!.target!.subjects![0]!.id!.should.equal('urn:restorecommerce:acs:names:role');
        rule!.target!.subjects![0]!.value!.should.equal('SimpleUser');
        rule!.target!.subjects![1]!.id!.should.equal('urn:restorecommerce:acs:names:roleScopingEntity');
        rule!.target!.subjects![1]!.value!.should.equal('urn:restorecommerce:acs:model:organization.Organization');

        should.exist(rule.target!.resources);
        rule.target!.resources!.should.have.length(1);
        rule.target!.resources![0]!.id!.should.equal('urn:restorecommerce:acs:names:model:entity');
        rule.target!.resources![0]!.value!.should.equal('urn:restorecommerce:acs:model:location.Location');

        should.exist(rule.target!.actions);
        rule.target!.actions!.should.have.length(1);
        rule.target!.actions![0]!.id!.should.equal('urn:oasis:names:tc:xacml:1.0:action:action-id');
        rule.target!.actions![0]!.value!.should.equal('urn:restorecommerce:acs:names:action:read');
      });
      it('should return filtered rules for both Location and Organization resource', async (): Promise<void> => {
        const accessRequest = testUtils.buildRequest({
          subjectID: 'Alice',
          subjectRole: 'SimpleUser',
          resourceType: ['urn:restorecommerce:acs:model:location.Location', 'urn:restorecommerce:acs:model:organization.Organization'],
          roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          roleScopingInstance: 'SuperOrg1',
          actionType: 'urn:restorecommerce:acs:names:action:read',
        });
        testUtils.marshallRequest(accessRequest);
        const result = await accessControlService.whatIsAllowed(accessRequest);
        should.exist(result);
        should.exist(result.policy_sets);
        result.policy_sets!.should.be.length(1);

        should.exist(result.policy_sets![0]!.policies);
        result.policy_sets![0]!.policies!.should.be.length(2); // location and Org Policy
        result.policy_sets![0]!.policies![0]!.id!.should.equal('policyA');
        result.policy_sets![0]!.policies![1]!.id!.should.equal('policyB');
        should.exist(result.policy_sets![0]!.policies![0]!.rules);
        result.policy_sets![0]!.policies![0]!.rules!.should.have.length(2);
        result.policy_sets![0]!.policies![1]!.rules!.should.have.length(2); // ruleAA5 and ruleAA6 for Organization resource

        // validate Location Rule
        const rule = result.policy_sets![0]!.policies![0]!.rules![0];
        should.exist(rule.target);
        should.exist(rule!.target!.subjects);
        rule!.target!.subjects!.should.have.length(2);
        rule!.target!.subjects![0]!.id!.should.equal('urn:restorecommerce:acs:names:role');
        rule!.target!.subjects![0]!.value!.should.equal('SimpleUser');
        rule!.target!.subjects![1]!.id!.should.equal('urn:restorecommerce:acs:names:roleScopingEntity');
        rule!.target!.subjects![1]!.value!.should.equal('urn:restorecommerce:acs:model:organization.Organization');

        should.exist(rule.target!.resources);
        rule.target!.resources!.should.have.length(1);
        rule.target!.resources![0]!.id!.should.equal('urn:restorecommerce:acs:names:model:entity');
        rule.target!.resources![0]!.value!.should.equal('urn:restorecommerce:acs:model:location.Location');

        should.exist(rule.target!.actions);
        rule.target!.actions!.should.have.length(1);
        rule.target!.actions![0]!.id!.should.equal('urn:oasis:names:tc:xacml:1.0:action:action-id');
        rule.target!.actions![0]!.value!.should.equal('urn:restorecommerce:acs:names:action:read');

        // validate Organization Rule
        const orgRule = result.policy_sets![0]!.policies![1]!.rules![0];
        should.exist(orgRule.target);
        should.exist(orgRule!.target!.subjects);
        orgRule!.target!.subjects!.should.have.length(2);
        orgRule!.target!.subjects![0]!.id!.should.equal('urn:restorecommerce:acs:names:role');
        orgRule!.target!.subjects![0]!.value!.should.equal('SimpleUser');
        orgRule!.target!.subjects![1]!.id!.should.equal('urn:restorecommerce:acs:names:roleScopingEntity');
        orgRule!.target!.subjects![1]!.value!.should.equal('urn:restorecommerce:acs:model:organization.Organization');

        should.exist(orgRule.target!.resources);
        orgRule.target!.resources!.should.have.length(1);
        orgRule.target!.resources![0]!.id!.should.equal('urn:restorecommerce:acs:names:model:entity');
        orgRule.target!.resources![0]!.value!.should.equal('urn:restorecommerce:acs:model:organization.Organization'); // entity should be Org

        should.exist(orgRule.target!.actions);
        orgRule.target!.actions!.should.have.length(1);
        orgRule.target!.actions![0]!.id!.should.equal('urn:oasis:names:tc:xacml:1.0:action:action-id');
        orgRule.target!.actions![0]!.value!.should.equal('urn:restorecommerce:acs:names:action:read');
      });
      it('should return filtered rules for both Location and Organization resource with resource IDs', async (): Promise<void> => {
        const accessRequest = testUtils.buildRequest({
          subjectID: 'Alice',
          subjectRole: 'SimpleUser',
          resourceType: ['urn:restorecommerce:acs:model:location.Location', 'urn:restorecommerce:acs:model:organization.Organization'],
          resourceID: ['Location 1', 'Organization 1'],
          roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          roleScopingInstance: 'SuperOrg1',
          actionType: 'urn:restorecommerce:acs:names:action:read',
        });
        testUtils.marshallRequest(accessRequest);
        const result = await accessControlService.whatIsAllowed(accessRequest);
        // result is same as above test
        should.exist(result);
        should.exist(result.policy_sets);
        result.policy_sets!.should.be.length(1);

        should.exist(result.policy_sets![0]!.policies);
        result.policy_sets![0]!.policies!.should.be.length(2); // location and Org Policy
        result.policy_sets![0]!.policies![0]!.id!.should.equal('policyA');
        result.policy_sets![0]!.policies![1]!.id!.should.equal('policyB');
        should.exist(result.policy_sets![0]!.policies![0]!.rules);
        result.policy_sets![0]!.policies![0]!.rules!.should.have.length(2);
        result.policy_sets![0]!.policies![1]!.rules!.should.have.length(2); // ruleAA5 and ruleAA6 for Organization resource

        // validate Location Rule
        const rule = result.policy_sets![0]!.policies![0]!.rules![0];
        should.exist(rule.target);
        should.exist(rule!.target!.subjects);
        rule!.target!.subjects!.should.have.length(2);
        rule!.target!.subjects![0]!.id!.should.equal('urn:restorecommerce:acs:names:role');
        rule!.target!.subjects![0]!.value!.should.equal('SimpleUser');
        rule!.target!.subjects![1]!.id!.should.equal('urn:restorecommerce:acs:names:roleScopingEntity');
        rule!.target!.subjects![1]!.value!.should.equal('urn:restorecommerce:acs:model:organization.Organization');

        should.exist(rule.target!.resources);
        rule.target!.resources!.should.have.length(1);
        rule.target!.resources![0]!.id!.should.equal('urn:restorecommerce:acs:names:model:entity');
        rule.target!.resources![0]!.value!.should.equal('urn:restorecommerce:acs:model:location.Location');

        should.exist(rule.target!.actions);
        rule.target!.actions!.should.have.length(1);
        rule.target!.actions![0]!.id!.should.equal('urn:oasis:names:tc:xacml:1.0:action:action-id');
        rule.target!.actions![0]!.value!.should.equal('urn:restorecommerce:acs:names:action:read');

        // validate Organization Rule
        const orgRule = result.policy_sets![0]!.policies![1]!.rules![0];
        should.exist(orgRule.target);
        should.exist(orgRule!.target!.subjects);
        orgRule!.target!.subjects!.should.have.length(2);
        orgRule!.target!.subjects![0]!.id!.should.equal('urn:restorecommerce:acs:names:role');
        orgRule!.target!.subjects![0]!.value!.should.equal('SimpleUser');
        orgRule!.target!.subjects![1]!.id!.should.equal('urn:restorecommerce:acs:names:roleScopingEntity');
        orgRule!.target!.subjects![1]!.value!.should.equal('urn:restorecommerce:acs:model:organization.Organization');

        should.exist(orgRule.target!.resources);
        orgRule.target!.resources!.should.have.length(1);
        orgRule.target!.resources![0]!.id!.should.equal('urn:restorecommerce:acs:names:model:entity');
        orgRule.target!.resources![0]!.value!.should.equal('urn:restorecommerce:acs:model:organization.Organization'); // entity should be Org

        should.exist(orgRule.target!.actions);
        orgRule.target!.actions!.should.have.length(1);
        orgRule.target!.actions![0]!.id!.should.equal('urn:oasis:names:tc:xacml:1.0:action:action-id');
        orgRule.target!.actions![0]!.value!.should.equal('urn:restorecommerce:acs:names:action:read');
      });
      it('should return PERMIT and DENY rules for both Location and Organization resource with resource IDs with invalid target scoping instance', async (): Promise<void> => {
        const accessRequest = testUtils.buildRequest({
          subjectID: 'Alice',
          subjectRole: 'SimpleUser',
          resourceType: ['urn:restorecommerce:acs:model:location.Location', 'urn:restorecommerce:acs:model:organization.Organization'],
          resourceID: ['Location 1', 'Organization 1'],
          roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          roleScopingInstance: 'SuperOrg1',
          actionType: 'urn:restorecommerce:acs:names:action:read',
          targetScopingInstance: 'invalidOrg', // invalidOrg targe scope
        });
        testUtils.marshallRequest(accessRequest);
        const result = await accessControlService.whatIsAllowed(accessRequest);

        should.exist(result);
        should.exist(result.policy_sets);
        result.policy_sets!.should.be.length(1);

        // as evaluation of target scope is done in acs-client for read operations - with returned Reversequery PolicySet read response
        // both PERMIT and DENY rules are returned
        should.exist(result.policy_sets![0]!.policies);
        result.policy_sets![0]!.policies!.should.be.length(2); // location and Org Policy
        result.policy_sets![0]!.policies![0]!.id!.should.equal('policyA');
        result.policy_sets![0]!.policies![1]!.id!.should.equal('policyB');
        should.exist(result.policy_sets![0]!.policies![0]!.rules);
        result.policy_sets![0]!.policies![0]!.rules!.should.have.length(2); // ruleAA1 PERMIT and rule AA3 DENY for location resource
        result.policy_sets![0]!.policies![1]!.rules!.should.have.length(2); // ruleAA5 PERMIT and ruleAA6 DENY for Organization resource

        // validate Location Rules
        const rule1 = result.policy_sets![0]!.policies![0]!.rules![0];
        rule1.id!.should.equal('ruleAA1');
        rule1.effect!.should.equal('PERMIT');
        const rule2 = result.policy_sets![0]!.policies![0]!.rules![1];
        rule2.id!.should.equal('ruleAA3');
        rule2.effect!.should.equal('DENY');

        // validate Organization Rules
        const rule3 = result.policy_sets![0]!.policies![1]!.rules![0];
        rule3.id!.should.equal('ruleAA5');
        rule3.effect!.should.equal('PERMIT');
        const rule4 = result.policy_sets![0]!.policies![1]!.rules![1];
        rule4.id!.should.equal('ruleAA6');
        rule4.effect!.should.equal('DENY');
      });
      it('should return only fallback rule when targets don\'t match', async (): Promise<void> => {
        const accessRequest = testUtils.buildRequest({
          subjectID: 'Alice',
          subjectRole: 'SimpleUser',
          roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          roleScopingInstance: 'Org1',
          resourceType: 'urn:restorecommerce:acs:model:user.User',
          resourceID: 'DoesNotExist',
          actionType: 'urn:restorecommerce:acs:names:action:read',
        });
        testUtils.marshallRequest(accessRequest);
        const result = await accessControlService.whatIsAllowed(accessRequest);

        should.exist(result);
        should.exist(result.policy_sets);
        result.policy_sets!.should.be.length(1);

        should.exist(result.policy_sets![0]!.policies);
        result.policy_sets![0]!.policies!.should.be.length(1);
        should.exist(result.policy_sets![0]!.policies![0]!.rules);
        result.policy_sets![0]!.policies![0]!.rules!.should.have.length(1);
        result.policy_sets![0]!.policies![0]!.rules![0]!.effect!.should.equal(Response_Decision.DENY);
      });
    });
  });
});
