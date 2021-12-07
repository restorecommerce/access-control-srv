// Tests for isAllowed and whatIsAllowed for specific properties

import * as mocha from 'mocha';
import * as should from 'should';

import * as core from '../src/core';
import { Worker } from '../src/worker';
import * as testUtils from './utils';

import { createServiceConfig } from '@restorecommerce/service-config';
import { createLogger } from '@restorecommerce/logger';
import { GrpcClient } from '@restorecommerce/grpc-client';

import * as yaml from 'js-yaml';
import * as fs from 'fs';
import { updateConfig } from '@restorecommerce/acs-client';

let cfg: any;
let logger;
let client: GrpcClient;
let worker: Worker;
let ruleService: any, policyService: any, policySetService: any;
let accessControlService: any;
let rules, policies, policySets;

const setupService = async (): Promise<void> => {
  cfg = createServiceConfig(process.cwd() + '/test');
  logger = createLogger(cfg.get('logger'));

  worker = new Worker();
  await worker.start(cfg, logger);

  client = new GrpcClient(cfg.get('client:policy_set'), logger);
  policySetService = client.policy_set;
  client = new GrpcClient(cfg.get('client:policy'), logger);
  policyService = client.policy;
  client = new GrpcClient(cfg.get('client:rule'), logger);
  ruleService = client.rule;
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
  const yamlPolicies = yaml.load(fs.readFileSync(policiesFile));
  const marshalled = testUtils.marshallYamlPolicies(yamlPolicies);

  rules = marshalled.rules;
  policies = marshalled.policies;
  policySets = marshalled.policySets;

  client = new GrpcClient(cfg.get('client:acs-srv'), logger);
  accessControlService = client['acs-srv'];
};

const create = async (policiesFile: string): Promise<void> => {
  await load(policiesFile);
  let resp = await policySetService.create({
    items: policySets
  });
  await policyService.create({
    items: policies
  });
  await ruleService.create({
    items: rules
  });
};

describe('testing access control', () => {
  before(async () => {
    await setupService();
    // disable authorization
    cfg.set('authorization:enabled', false);
    cfg.set('authorization:enforce', false);
    updateConfig(cfg);
  });
  after(async () => {
    await client.close();
    await worker.stop();
  });
  describe('isAllowed()', () => {
    before(async () => {
      await create('./test/fixtures/properties.yml');
    });
    after(async function (): Promise<void> {
      this.timeout(5000);
      await truncate();
    });
    it('should PERMIT Reading Location with id and name properties', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceProperty: [ 'urn:restorecommerce:acs:model:location.Location#id', 'urn:restorecommerce:acs:model:location.Location#name'],
        resourceID: 'Bob',
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: 'Org1'
      });
      testUtils.marshallRequest(accessRequest);

      const result = await accessControlService.isAllowed(accessRequest);
      should.exist(result);
      should.exist(result.decision);
      result.decision.should.equal(core.Decision.PERMIT);
      result.operation_status.code.should.equal(200);
      result.operation_status.message.should.equal('success');
    });
    it('should DENY Reading Location with id, name and description (desc not allowed) properties', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceProperty: [ 'urn:restorecommerce:acs:model:location.Location#id', 'urn:restorecommerce:acs:model:location.Location#name', 'urn:restorecommerce:acs:model:location.Location#description'],
        resourceID: 'Bob',
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: 'Org1'
      });
      testUtils.marshallRequest(accessRequest);

      const result = await accessControlService.isAllowed(accessRequest);
      should.exist(result);
      should.exist(result.decision);
      result.decision.should.equal(core.Decision.DENY);
      result.operation_status.code.should.equal(200);
      result.operation_status.message.should.equal('success');
    });
  });
  describe('testing whatIsAllowed', () => {
    before(async () => {
      // disable authorization
      cfg.set('authorization:enabled', false);
      cfg.set('authorization:enforce', false);
      updateConfig(cfg);
      await create('./test/fixtures/properties.yml');
    });
    after(async () => {
      await truncate();
    });
    it('should return filtered rules for Location resource with id and name properties', async (): Promise<void> => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceProperty: [ 'urn:restorecommerce:acs:model:location.Location#id', 'urn:restorecommerce:acs:model:location.Location#name'],
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'SuperOrg1',
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: 'Org1'
      });
      testUtils.marshallRequest(accessRequest);
      const result = await accessControlService.whatIsAllowed(accessRequest);
      should.exist(result);
      should.not.exist(result.error);
      should.exist(result.policy_sets);
      result.policy_sets.should.be.length(1);

      should.exist(result.policy_sets[0].policies);
      result.policy_sets[0].policies.should.be.length(1);
      should.exist(result.policy_sets[0].policies[0].rules);
      result.policy_sets[0].policies[0].rules.should.have.length(2);

      const rule = result.policy_sets[0].policies[0].rules[0];
      should.exist(rule.target);
      should.exist(rule.target.subject);
      rule.target.subject.should.have.length(2);
      rule.target.subject[0].id.should.equal('urn:restorecommerce:acs:names:role');
      rule.target.subject[0].value.should.equal('SimpleUser');
      rule.target.subject[1].id.should.equal('urn:restorecommerce:acs:names:roleScopingEntity');
      rule.target.subject[1].value.should.equal('urn:restorecommerce:acs:model:organization.Organization');

      should.exist(rule.target.resources);
      rule.target.resources.should.have.length(3);
      rule.target.resources[0].id.should.equal('urn:restorecommerce:acs:names:model:entity');
      rule.target.resources[0].value.should.equal('urn:restorecommerce:acs:model:location.Location');
      rule.target.resources[1].id.should.equal('urn:restorecommerce:acs:names:model:property');
      rule.target.resources[1].value.should.equal('urn:restorecommerce:acs:model:location.Location#id');
      rule.target.resources[2].id.should.equal('urn:restorecommerce:acs:names:model:property');
      rule.target.resources[2].value.should.equal('urn:restorecommerce:acs:model:location.Location#name');

      should.exist(rule.target.action);
      rule.target.action.should.have.length(1);
      rule.target.action[0].id.should.equal('urn:oasis:names:tc:xacml:1.0:action:action-id');
      rule.target.action[0].value.should.equal('urn:restorecommerce:acs:names:action:read');
    });
  });
});