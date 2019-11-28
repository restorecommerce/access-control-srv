import * as mocha from 'mocha';
import * as should from 'should';

import * as core from '../lib/core';
import { Worker } from '../lib/worker';
import * as testUtils from './utils';

import * as srvConfig from '@restorecommerce/service-config';
import { Logger } from '@restorecommerce/logger';
import { Client } from '@restorecommerce/grpc-client';

import * as yaml from 'js-yaml';
import * as fs from 'fs';

let cfg: any;
let logger;
let client: Client;
let worker: Worker;
let ruleService: any, policyService: any, policySetService: any;
let accessControlService: any;
let rules, policies, policySets;

describe('testing microservice', () => {
  describe('testing resource ownership', () => {
    before(async () => {
      await setupService();
      await load('./test/fixtures/conditions.yml');
    });
    after(async () => {
      await client.end();
      await worker.stop();
    });
    describe('testing create() operations', () => {
      it('it should insert policy sets', async () => {
        const result = await policySetService.create({
          items: policySets
        });
        should.exist(result);
        should.not.exist(result.error);
        should.exist(result.data);
        should.exist(result.data.items);
        result.data.items.should.be.length(policySets.length);
      });

      it('should insert policies', async () => {
        const result = await policyService.create({
          items: policies
        });
        should.exist(result);
        should.not.exist(result.error);
        should.exist(result.data);
        should.exist(result.data.items);
        result.data.items.should.be.length(policies.length);
      });

      it('should insert rules', async () => {
        const result = await ruleService.create({
          items: rules
        });
        should.exist(result);
        should.not.exist(result.error);
        should.exist(result.data);
        should.exist(result.data.items);
        result.data.items.should.be.length(rules.length);
      });

      it('should update in-memory policies when creating resources', async () => {
        const accessController = worker.accessController;
        should.exist(accessController.policySets);
        accessController.policySets.should.have.size(1);

        // checking policies
        const policySet: [string, core.PolicySet] = accessController.policySets.entries().next().value;
        should.exist(policySet[1].combinables);
        policySet[1].combinables.should.have.size(1);

        // checking policy rules
        const policy: [string, core.Policy] = policySet[1].combinables.entries().next().value;
        should.exist(policy[1].combinables);
        policy[1].combinables.should.have.size(3);
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
                "policyA", "policyB"
              ],
              meta: {
                owner: [],
                modified_by: ''
              }
            },
          ]
        }, {});

        should.exist(result);
        should.exist(result.data);
        should.exist(result.data.items);
        result.data.items.should.have.length(1);

        const updatedPS = result.data.items[0];
        should.exist(updatedPS.name);
        should.exist(updatedPS.policies);
        updatedPS.name.should.equal('Policy set A v2');

        updatedPS.policies.should.have.length(2);
        should.exist(updatedPS.policies[0]);
        updatedPS.policies[0].should.equal('policyA');
        updatedPS.policies[1].should.equal('policyB');
      });
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
        await ruleService.delete({
          ids: rules.map((r) => { return r.id; })
        });
        const result = await ruleService.read();
        should.exist(result);
        should.not.exist(result.error);
        should.exist(result.data);
        should.exist(result.data.items);
        result.data.items.should.be.empty();
      });

      it('should update in-memory policies by removing rules', () => {
        const accessController = worker.accessController;

        for (let [, policySet] of accessController.policySets) {
          for (let [, policy] of policySet.combinables) {
            should.exist(policy.combinables);
            policy.combinables.should.have.size(0);
          }
        }
      });

      it('should delete policies', async () => {
        await policyService.delete({
          ids: policies.map((p) => { return p.id; })
        });
        const result = await policyService.read();
        should.exist(result);
        should.not.exist(result.error);
        should.exist(result.data);
        should.exist(result.data.items);
        result.data.items.should.be.empty();
      });

      it('should update in-memory policy sets by removing policies', () => {
        const accessController = worker.accessController;

        for (let [, policySet] of accessController.policySets) {
          should.exist(policySet.combinables);
          policySet.combinables.should.have.size(0);
        }
      });

      it('should delete policy sets', async () => {
        await policySetService.delete({
          ids: policySets.map((p) => { return p.id; })
        });
        const result = await policySetService.read();
        should.exist(result);
        should.not.exist(result.error);
        should.exist(result.data);
        should.exist(result.data.items);
        result.data.items.should.be.empty();
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
      await client.end();
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
          resourceType: 'urn:restorecommerce:acs:model:user.User',
          resourceProperty: 'urn:restorecommerce:acs:model:user.User#name',
          resourceID: 'Bob',
          actionType: 'urn:restorecommerce:acs:names:action:read',
        });
        testUtils.marshallRequest(accessRequest);

        const result = await accessControlService.isAllowed(accessRequest);
        should.exist(result);
        should.not.exist(result.error);
        should.exist(result.data);
        should.exist(result.data.decision);
        result.data.decision.should.equal(core.Decision.PERMIT);
      });

      it('should throw DENY', async () => {
        const accessRequest = testUtils.buildRequest({
          subjectID: 'Alice',
          resourceType: 'urn:restorecommerce:acs:model:user.User',
          resourceProperty: 'urn:restorecommerce:acs:model:user.User#name',
          resourceID: 'Bob',
          actionType: 'urn:restorecommerce:acs:names:action:modify'
        });
        testUtils.marshallRequest(accessRequest);

        const result = await accessControlService.isAllowed(accessRequest);
        should.exist(result);
        should.not.exist(result.error);
        should.exist(result.data);
        should.exist(result.data.decision);
        result.data.decision.should.equal(core.Decision.DENY);
      });

      it('should throw DENY due to invalid context', async () => {
        const accessRequest = testUtils.buildRequest({
          subjectID: 'Alice',
          resourceType: 'urn:restorecommerce:acs:model:user.User',
          resourceProperty: 'urn:restorecommerce:acs:model:user.User#name',
          resourceID: 'Alice',
          actionType: 'urn:restorecommerce:acs:names:action:modify',
        });
        accessRequest.context = null;

        const result = await accessControlService.isAllowed(accessRequest);
        should.exist(result);
        should.not.exist(result.error);
        should.exist(result.data);
        should.exist(result.data.decision);
        result.data.decision.should.equal(core.Decision.DENY);
      });

      it('should throw INDETERMINATE', async () => {
        const accessRequest = testUtils.buildRequest({
          subjectID: 'Alice',
          resourceType: 'urn:restorecommerce:acs:model:unknown.Unknown',
          resourceProperty: 'urn:restorecommerce:acs:model:unknown.Unknown#random',
          resourceID: 'UnknownID',
          actionType: 'urn:restorecommerce:acs:names:action:read',
        });
        testUtils.marshallRequest(accessRequest);

        const result = await accessControlService.isAllowed(accessRequest);
        should.exist(result);
        should.not.exist(result.error);
        should.exist(result.data);
        should.exist(result.data.decision);
        result.data.decision.should.equal(core.Decision.INDETERMINATE);
      });
    });
    describe('testing whatIsAllowed', () => {
      before(async () => {
        await create('./test/fixtures/roleScopes.yml');
      });
      after(async () => {
        await truncate();
      });
      it('should return filtered rules', async function (): Promise<void> {
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
        should.not.exist(result.error);
        should.exist(result.data);
        should.exist(result.data.policy_sets);
        result.data.policy_sets.should.be.length(1);

        should.exist(result.data.policy_sets[0].policies);
        result.data.policy_sets[0].policies.should.be.length(1);
        should.exist(result.data.policy_sets[0].policies[0].rules);
        result.data.policy_sets[0].policies[0].rules.should.have.length(2);

        const rule = result.data.policy_sets[0].policies[0].rules[0];
        should.exist(rule.target);
        should.exist(rule.target.subject);
        rule.target.subject.should.have.length(2);
        rule.target.subject[0].id.should.equal('urn:restorecommerce:acs:names:role');
        rule.target.subject[0].value.should.equal('SimpleUser');
        rule.target.subject[1].id.should.equal('urn:restorecommerce:acs:names:roleScopingEntity');
        rule.target.subject[1].value.should.equal('urn:restorecommerce:acs:model:organization.Organization');

        should.exist(rule.target.resources);
        rule.target.resources.should.have.length(1);
        rule.target.resources[0].id.should.equal('urn:restorecommerce:acs:names:model:entity');
        rule.target.resources[0].value.should.equal('urn:restorecommerce:acs:model:location.Location');

        should.exist(rule.target.action);
        rule.target.action.should.have.length(1);
        rule.target.action[0].id.should.equal('urn:oasis:names:tc:xacml:1.0:action:action-id');
        rule.target.action[0].value.should.equal('urn:restorecommerce:acs:names:action:read');
      });
      it('should return return only fallback rule when targets don\'t match', async function (): Promise<void> {
        const accessRequest = testUtils.buildRequest({
          subjectID: 'Alice',
          resourceType: 'urn:restorecommerce:acs:model:user.User',
          resourceID: 'DoesNotExist',
          actionType: 'urn:restorecommerce:acs:names:action:read',
        });
        testUtils.marshallRequest(accessRequest);
        const result = await accessControlService.whatIsAllowed(accessRequest);

        should.exist(result);
        should.not.exist(result.error);
        should.exist(result.data);
        should.exist(result.data.policy_sets);
        result.data.policy_sets.should.be.length(1);

        should.exist(result.data.policy_sets[0].policies);
        result.data.policy_sets[0].policies.should.be.length(1);
        should.exist(result.data.policy_sets[0].policies[0].rules);
        result.data.policy_sets[0].policies[0].rules.should.have.length(1);
        result.data.policy_sets[0].policies[0].rules[0].effect.should.equal(core.Decision.DENY);
      });
    });
  });
});


async function setupService(): Promise<void> {
  cfg = srvConfig(process.cwd() + '/test');
  logger = new Logger(cfg.get('logger'));

  worker = new Worker();
  await worker.start(cfg, logger);

  client = new Client(cfg.get('client:policy_set'), logger);
  policySetService = await client.connect();
  client = new Client(cfg.get('client:policy'), logger);
  policyService = await client.connect();
  client = new Client(cfg.get('client:rule'), logger);
  ruleService = await client.connect();
}

async function truncate(): Promise<void> {
  await policySetService.delete({
    collection: true
  });
  await policyService.delete({
    collection: true
  });
  await ruleService.delete({
    collection: true
  });
}

async function load(policiesFile: string): Promise<void> {
  // load from fixtures
  const yamlPolicies = yaml.safeLoad(fs.readFileSync(policiesFile));
  const marshalled = testUtils.marshallYamlPolicies(yamlPolicies);

  rules = marshalled.rules;
  policies = marshalled.policies;
  policySets = marshalled.policySets;

  client = new Client(cfg.get('client:acs'), logger);
  accessControlService = await client.connect();
}

async function create(policiesFile: string): Promise<void> {
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
}
