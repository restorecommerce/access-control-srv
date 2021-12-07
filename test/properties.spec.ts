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

const validateWhatIsAllowedLocationResponse = (result: any, withoutProps?: boolean) => {
  should.exist(result);
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

  if (withoutProps) {
    should.exist(rule.target.resources);
    rule.target.resources.should.have.length(1);
    rule.target.resources[0].id.should.equal('urn:restorecommerce:acs:names:model:entity');
    rule.target.resources[0].value.should.equal('urn:restorecommerce:acs:model:location.Location');
  } else {
    should.exist(rule.target.resources);
    rule.target.resources.should.have.length(3);
    rule.target.resources[0].id.should.equal('urn:restorecommerce:acs:names:model:entity');
    rule.target.resources[0].value.should.equal('urn:restorecommerce:acs:model:location.Location');
    rule.target.resources[1].id.should.equal('urn:restorecommerce:acs:names:model:property');
    rule.target.resources[1].value.should.equal('urn:restorecommerce:acs:model:location.Location#id');
    rule.target.resources[2].id.should.equal('urn:restorecommerce:acs:names:model:property');
    rule.target.resources[2].value.should.equal('urn:restorecommerce:acs:model:location.Location#name');
  }

  should.exist(rule.target.action);
  rule.target.action.should.have.length(1);
  rule.target.action[0].id.should.equal('urn:oasis:names:tc:xacml:1.0:action:action-id');
  rule.target.action[0].value.should.equal('urn:restorecommerce:acs:names:action:read');
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
    // READ - isAllowed
    it('should PERMIT reading Location with id and name properties', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceProperty: ['urn:restorecommerce:acs:model:location.Location#id', 'urn:restorecommerce:acs:model:location.Location#name'],
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
    it('should PERMIT reading Location with id property', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceProperty: ['urn:restorecommerce:acs:model:location.Location#id'],
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
    it('should DENY reading Location with id, name and description (description property not allowed) properties', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceProperty: ['urn:restorecommerce:acs:model:location.Location#id', 'urn:restorecommerce:acs:model:location.Location#name', 'urn:restorecommerce:acs:model:location.Location#description'],
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
    it('should DENY reading Location when no properties are provided at all (since the properties are defined on Rule)', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
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
    // modify - isAllowed
    it('should PERMIT modifying Location with id and name properties', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceProperty: ['urn:restorecommerce:acs:model:location.Location#id', 'urn:restorecommerce:acs:model:location.Location#name'],
        resourceID: 'Bob',
        actionType: 'urn:restorecommerce:acs:names:action:modify',
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
    it('should PERMIT modifying Location with id property', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceProperty: ['urn:restorecommerce:acs:model:location.Location#id'],
        resourceID: 'Bob',
        actionType: 'urn:restorecommerce:acs:names:action:modify',
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
    it('should DENY modifying Location with id, name and description (description property not allowed) properties', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceProperty: ['urn:restorecommerce:acs:model:location.Location#id', 'urn:restorecommerce:acs:model:location.Location#name', 'urn:restorecommerce:acs:model:location.Location#description'],
        resourceID: 'Bob',
        actionType: 'urn:restorecommerce:acs:names:action:modify',
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
    it('should DENY modifying Location when no properties are provided at all (since the properties are defined on Rule)', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceID: 'Bob',
        actionType: 'urn:restorecommerce:acs:names:action:modify',
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
    it('should return empty obligation and filtered rules for Location resource with id and name properties', async (): Promise<void> => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceProperty: ['urn:restorecommerce:acs:model:location.Location#id', 'urn:restorecommerce:acs:model:location.Location#name'],
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'SuperOrg1',
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: 'Org1'
      });
      testUtils.marshallRequest(accessRequest);
      const result = await accessControlService.whatIsAllowed(accessRequest);
      validateWhatIsAllowedLocationResponse(result);
      // validate obligation
      result.obligation.should.be.empty();
    });
    it('should return empty obligation and filtered rules for Location resource with only name property', async (): Promise<void> => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceProperty: ['urn:restorecommerce:acs:model:location.Location#name'],
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'SuperOrg1',
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: 'Org1'
      });
      testUtils.marshallRequest(accessRequest);
      const result = await accessControlService.whatIsAllowed(accessRequest);
      validateWhatIsAllowedLocationResponse(result);
      // validate obligation
      result.obligation.should.be.empty();
    });
    it('should return obligation (for desciption properties) along with filtered rules for Location resource with id and name properties', async (): Promise<void> => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceProperty: ['urn:restorecommerce:acs:model:location.Location#id', 'urn:restorecommerce:acs:model:location.Location#name', 'urn:restorecommerce:acs:model:location.Location#properties'],
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'SuperOrg1',
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: 'Org1'
      });
      testUtils.marshallRequest(accessRequest);
      const result = await accessControlService.whatIsAllowed(accessRequest);
      validateWhatIsAllowedLocationResponse(result);
      // validate obligation
      result.obligation.should.be.length(1);
      result.obligation[0].id.should.equal('urn:restorecommerce:acs:names:model:entity');
      result.obligation[0].value.should.equal('urn:restorecommerce:acs:model:location.Location');
      result.obligation[0].attribute[0].id.should.equal('urn:restorecommerce:acs:names:obligation:maskedProperty');
      result.obligation[0].attribute[0].value.should.equal('urn:restorecommerce:acs:model:location.Location#properties');
    });
    it('should return only DENY rule for Location resource with out any properties in request', async (): Promise<void> => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'SuperOrg1',
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: 'Org1'
      });
      testUtils.marshallRequest(accessRequest);
      const result = await accessControlService.whatIsAllowed(accessRequest);
      should.exist(result.policy_sets);
      result.policy_sets.should.be.length(1);
      result.policy_sets[0].policies.should.be.length(1);
      result.policy_sets[0].policies[0].rules.should.be.length(1);
      result.policy_sets[0].policies[0].rules[0].id.should.equal('ruleAA3');
      result.policy_sets[0].policies[0].rules[0].effect.should.equal('DENY');
      result.obligation.should.be.length(0);
    });
  });
  describe('testing isAllowed without properties defined in Rule', () => {
    before(async () => {
      // disable authorization
      cfg.set('authorization:enabled', false);
      cfg.set('authorization:enforce', false);
      updateConfig(cfg);
      await create('./test/fixtures/policy_sets_without_properties.yml');
    });
    after(async () => {
      await truncate();
    });
    it('should PERMIT reading Location with id and name properties', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceProperty: ['urn:restorecommerce:acs:model:location.Location#id', 'urn:restorecommerce:acs:model:location.Location#name'],
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
    it('should PERMIT reading Location when no properties provided', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceID: 'Bob',
        actionType: 'urn:restorecommerce:acs:names:action:modify',
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
  });
  describe('testing whatIsAllowed without properties defined in Rule', () => {
    before(async () => {
      // disable authorization
      cfg.set('authorization:enabled', false);
      cfg.set('authorization:enforce', false);
      updateConfig(cfg);
      await create('./test/fixtures/policy_sets_without_properties.yml');
    });
    after(async () => {
      await truncate();
    });
    it('should return empty obligation and filtered rules for Location resource with id and name properties', async (): Promise<void> => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceProperty: ['urn:restorecommerce:acs:model:location.Location#id', 'urn:restorecommerce:acs:model:location.Location#name'],
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'SuperOrg1',
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: 'Org1'
      });
      testUtils.marshallRequest(accessRequest);
      const result = await accessControlService.whatIsAllowed(accessRequest);
      validateWhatIsAllowedLocationResponse(result, true);
      // validate obligation
      result.obligation.should.be.empty();
    });
    it('should return empty obligation and filtered rules for Location resource with no properties in request', async (): Promise<void> => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'SuperOrg1',
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: 'Org1'
      });
      testUtils.marshallRequest(accessRequest);
      const result = await accessControlService.whatIsAllowed(accessRequest);
      validateWhatIsAllowedLocationResponse(result, true);
      // validate obligation
      result.obligation.should.be.empty();
    });
  });
});