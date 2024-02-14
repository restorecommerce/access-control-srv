// Tests for isAllowed and whatIsAllowed for specific properties
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
  const yamlPolicies = yaml.load(fs.readFileSync(policiesFile));
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
  should.exist(rule.target.subjects);
  rule.target.subjects.should.have.length(2);
  rule.target.subjects[0].id.should.equal('urn:restorecommerce:acs:names:role');
  rule.target.subjects[0].value.should.equal('SimpleUser');
  rule.target.subjects[1].id.should.equal('urn:restorecommerce:acs:names:roleScopingEntity');
  rule.target.subjects[1].value.should.equal('urn:restorecommerce:acs:model:organization.Organization');

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

  should.exist(rule.target.actions);
  rule.target.actions.should.have.length(1);
  rule.target.actions[0].id.should.equal('urn:oasis:names:tc:xacml:1.0:action:action-id');
  rule.target.actions[0].value.should.equal('urn:restorecommerce:acs:names:action:read');
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
    await worker.stop();
  });

  describe('testing isAllowed with multiple entities and different properties in each entity', () => {
    before(async () => {
      // disable authorization
      cfg.set('authorization:enabled', false);
      cfg.set('authorization:enforce', false);
      updateConfig(cfg);
      await create('./test/fixtures/multiple_operations.yml');
    });
    after(async () => {
      await truncate();
    });

    it('should DENY executing multiple Operations for target scope which subject does not have access', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org2',
        resourceType: ['mutation.Test1', 'mutation.Test2'],
        resourceID: ['mutation.Test1', 'mutation.Test2'],
        actionType: 'urn:restorecommerce:acs:names:action:execute',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: ['Org1', 'Org1']
      });
      testUtils.marshallRequest(accessRequest);

      const result = await accessControlService.isAllowed(accessRequest);
      should.exist(result);
      should.exist(result.decision);
      result.decision.should.equal(Response_Decision.DENY);
      result.operation_status.code.should.equal(200);
      result.operation_status.message.should.equal('success');
    });

    it('should PERMIT executing multiple Operations for target scope which subject has access', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: ['mutation.Test1', 'mutation.Test2'],
        resourceID: ['mutation.Test1', 'mutation.Test2'],
        actionType: 'urn:restorecommerce:acs:names:action:execute',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: ['Org1', 'Org1']
      });
      testUtils.marshallRequest(accessRequest);

      const result = await accessControlService.isAllowed(accessRequest);
      should.exist(result);
      should.exist(result.decision);
      result.decision.should.equal(Response_Decision.PERMIT);
      result.operation_status.code.should.equal(200);
      result.operation_status.message.should.equal('success');
    });
  });

  describe('isAllowed() for single entity', () => {
    before(async () => {
      await create('./test/fixtures/properties.yml');
    });
    after(async function (): Promise<void> {
      this.timeout(5000);
      await truncate();
    });
    // READ - isAllowed - Location Entity
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
      result.decision.should.equal(Response_Decision.PERMIT);
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
      result.decision.should.equal(Response_Decision.PERMIT);
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
      result.decision.should.equal(Response_Decision.DENY);
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
      result.decision.should.equal(Response_Decision.DENY);
      result.operation_status.code.should.equal(200);
      result.operation_status.message.should.equal('success');
    });
    // modify - isAllowed - Location Entity
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
      result.decision.should.equal(Response_Decision.PERMIT);
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
      result.decision.should.equal(Response_Decision.PERMIT);
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
      result.decision.should.equal(Response_Decision.DENY);
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
      result.decision.should.equal(Response_Decision.DENY);
      result.operation_status.code.should.equal(200);
      result.operation_status.message.should.equal('success');
    });
  });
  describe('testing whatIsAllowed for single entity', () => {
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
      should.not.exist(result.obligations);
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
      should.not.exist(result.obligations);
    });
    it('should return obligation (for description properties) along with filtered rules for Location resource with id and name properties', async (): Promise<void> => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceProperty: ['urn:restorecommerce:acs:model:location.Location#id', 'urn:restorecommerce:acs:model:location.Location#name', 'urn:restorecommerce:acs:model:location.Location#description'],
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
      result.obligations.should.be.length(1);
      result.obligations[0].id.should.equal('urn:restorecommerce:acs:names:model:entity');
      result.obligations[0].value.should.equal('urn:restorecommerce:acs:model:location.Location');
      result.obligations[0].attributes[0].id.should.equal('urn:restorecommerce:acs:names:obligation:maskedProperty');
      result.obligations[0].attributes[0].value.should.equal('urn:restorecommerce:acs:model:location.Location#description');
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
      should.not.exist(result.obligations);
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
      result.decision.should.equal(Response_Decision.PERMIT);
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
      result.decision.should.equal(Response_Decision.PERMIT);
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
      should.not.exist(result.obligations);
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
      should.not.exist(result.obligations);
    });
  });

  describe('testing isAllowed with multiple rules to mask property', () => {
    before(async () => {
      // disable authorization
      cfg.set('authorization:enabled', false);
      cfg.set('authorization:enforce', false);
      updateConfig(cfg);
      await create('./test/fixtures/multiple_rules_with_properties.yml');
    });
    after(async () => {
      await truncate();
    });
    it('should DENY for reading Location resource with id, name and description properties (description Deny rule)', async (): Promise<void> => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        resourceID: 'Bob',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceProperty: ['urn:restorecommerce:acs:model:location.Location#id', 'urn:restorecommerce:acs:model:location.Location#name', 'urn:restorecommerce:acs:model:location.Location#description'],
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'SuperOrg1',
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: 'Org1'
      });
      testUtils.marshallRequest(accessRequest);
      const result = await accessControlService.isAllowed(accessRequest);
      should.exist(result);
      should.exist(result.decision);
      result.decision.should.equal(Response_Decision.DENY);
      result.operation_status.code.should.equal(200);
      result.operation_status.message.should.equal('success');
    });
    it('should DENY for reading Location resource with description property (description Deny rule)', async (): Promise<void> => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        resourceID: 'Bob',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceProperty: ['urn:restorecommerce:acs:model:location.Location#description'],
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'SuperOrg1',
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: 'Org1'
      });
      testUtils.marshallRequest(accessRequest);
      const result = await accessControlService.isAllowed(accessRequest);
      should.exist(result);
      should.exist(result.decision);
      result.decision.should.equal(Response_Decision.DENY);
      result.operation_status.code.should.equal(200);
      result.operation_status.message.should.equal('success');
    });
    it('should PERMIT for reading Location resource with id and name property', async (): Promise<void> => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        resourceID: 'Bob',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceProperty: ['urn:restorecommerce:acs:model:location.Location#id', 'urn:restorecommerce:acs:model:location.Location#name'],
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'SuperOrg1',
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: 'Org1'
      });
      testUtils.marshallRequest(accessRequest);
      const result = await accessControlService.isAllowed(accessRequest);
      should.exist(result);
      should.exist(result.decision);
      result.decision.should.equal(Response_Decision.PERMIT);
      result.operation_status.code.should.equal(200);
      result.operation_status.message.should.equal('success');
    });
    it('should DENY reading Location resource with out any properties specified (as it will not be possible to evaluate masked properties from Deny rule)', async (): Promise<void> => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        resourceID: 'Bob',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'SuperOrg1',
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: 'Org1'
      });
      testUtils.marshallRequest(accessRequest);
      const result = await accessControlService.isAllowed(accessRequest);
      should.exist(result);
      should.exist(result.decision);
      result.decision.should.equal(Response_Decision.DENY);
      result.operation_status.code.should.equal(200);
      result.operation_status.message.should.equal('success');
    });
    it('should PERMIT for AdminUser reading Location resource with id, name and description properties', async (): Promise<void> => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'AdminUser',
        resourceID: 'Bob',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceProperty: ['urn:restorecommerce:acs:model:location.Location#id', 'urn:restorecommerce:acs:model:location.Location#name', 'urn:restorecommerce:acs:model:location.Location#description'],
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'SuperOrg1',
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: 'Org1'
      });
      testUtils.marshallRequest(accessRequest);
      const result = await accessControlService.isAllowed(accessRequest);
      should.exist(result);
      should.exist(result.decision);
      result.decision.should.equal(Response_Decision.PERMIT);
      result.operation_status.code.should.equal(200);
      result.operation_status.message.should.equal('success');
    });
    it('should PERMIT for AdminUser reading Location resource with out any properties specified in request', async (): Promise<void> => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'AdminUser',
        resourceID: 'Bob',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'SuperOrg1',
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: 'Org1'
      });
      testUtils.marshallRequest(accessRequest);
      const result = await accessControlService.isAllowed(accessRequest);
      should.exist(result);
      should.exist(result.decision);
      result.decision.should.equal(Response_Decision.PERMIT);
      result.operation_status.code.should.equal(200);
      result.operation_status.message.should.equal('success');
    });
    it('should PERMIT for AdminUser modifying Location resource with id, name and description properties', async (): Promise<void> => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'AdminUser',
        resourceID: 'Bob',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceProperty: ['urn:restorecommerce:acs:model:location.Location#id', 'urn:restorecommerce:acs:model:location.Location#name', 'urn:restorecommerce:acs:model:location.Location#description'],
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'SuperOrg1',
        actionType: 'urn:restorecommerce:acs:names:action:modify',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: 'Org1'
      });
      testUtils.marshallRequest(accessRequest);
      const result = await accessControlService.isAllowed(accessRequest);
      should.exist(result);
      should.exist(result.decision);
      result.decision.should.equal(Response_Decision.PERMIT);
      result.operation_status.code.should.equal(200);
      result.operation_status.message.should.equal('success');
    });
    it('should PERMIT for AdminUser modifying Location resource with out any properties specified in request', async (): Promise<void> => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'AdminUser',
        resourceID: 'Bob',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'SuperOrg1',
        actionType: 'urn:restorecommerce:acs:names:action:modify',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: 'Org1'
      });
      testUtils.marshallRequest(accessRequest);
      const result = await accessControlService.isAllowed(accessRequest);
      should.exist(result);
      should.exist(result.decision);
      result.decision.should.equal(Response_Decision.PERMIT);
      result.operation_status.code.should.equal(200);
      result.operation_status.message.should.equal('success');
    });
  });

  describe('testing whatIsAllowed with multiple rules to mask property', () => {
    before(async () => {
      // disable authorization
      cfg.set('authorization:enabled', false);
      cfg.set('authorization:enforce', false);
      updateConfig(cfg);
      await create('./test/fixtures/multiple_rules_with_properties.yml');
    });
    after(async () => {
      await truncate();
    });
    it('should return obligation for description property and filtered rules for Location resource request reading for id, name and description', async (): Promise<void> => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceProperty: ['urn:restorecommerce:acs:model:location.Location#id', 'urn:restorecommerce:acs:model:location.Location#name', 'urn:restorecommerce:acs:model:location.Location#description'],
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'SuperOrg1',
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: 'Org1'
      });
      testUtils.marshallRequest(accessRequest);
      const result = await accessControlService.whatIsAllowed(accessRequest);
      should.exist(result);
      // validate obligation
      result.obligations.should.be.length(1);
      result.obligations[0].id.should.equal('urn:restorecommerce:acs:names:model:entity');
      result.obligations[0].value.should.equal('urn:restorecommerce:acs:model:location.Location');
      result.obligations[0].attributes[0].id.should.equal('urn:restorecommerce:acs:names:obligation:maskedProperty');
      result.obligations[0].attributes[0].value.should.equal('urn:restorecommerce:acs:model:location.Location#description');
      // validate 2 rules
      result.policy_sets[0].policies[0].rules.should.be.length(2);
      result.policy_sets[0].policies[0].rules[0].id.should.equal('ruleAA1');
      result.policy_sets[0].policies[0].rules[1].id.should.equal('ruleAA2');
    });
    it('should return obligation for description property and filtered rules for Location resource request reading for description', async (): Promise<void> => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceProperty: ['urn:restorecommerce:acs:model:location.Location#description'],
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'SuperOrg1',
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: 'Org1'
      });
      testUtils.marshallRequest(accessRequest);
      const result = await accessControlService.whatIsAllowed(accessRequest);
      // validate obligation
      result.obligations.should.be.length(1);
      result.obligations[0].id.should.equal('urn:restorecommerce:acs:names:model:entity');
      result.obligations[0].value.should.equal('urn:restorecommerce:acs:model:location.Location');
      result.obligations[0].attributes[0].id.should.equal('urn:restorecommerce:acs:names:obligation:maskedProperty');
      result.obligations[0].attributes[0].value.should.equal('urn:restorecommerce:acs:model:location.Location#description');
      // validate 2 rules
      result.policy_sets[0].policies[0].rules.should.be.length(2);
      result.policy_sets[0].policies[0].rules[0].id.should.equal('ruleAA1');
      result.policy_sets[0].policies[0].rules[1].id.should.equal('ruleAA2');
    });
    it('should return empty obligation for description and filtered rules for Location resource request reading for id and name', async (): Promise<void> => {
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
      // validate obligation
      should.not.exist(result.obligations);
      // validate 2 rules
      result.policy_sets[0].policies[0].rules.should.be.length(2);
      result.policy_sets[0].policies[0].rules[0].id.should.equal('ruleAA1');
      result.policy_sets[0].policies[0].rules[1].id.should.equal('ruleAA2');
    });
    it('should return obligation for description property and filtered rules for Location resource request when no properties are specified in request', async (): Promise<void> => {
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
      // validate obligation
      result.obligations.should.be.length(1);
      result.obligations[0].id.should.equal('urn:restorecommerce:acs:names:model:entity');
      result.obligations[0].value.should.equal('urn:restorecommerce:acs:model:location.Location');
      result.obligations[0].attributes[0].id.should.equal('urn:restorecommerce:acs:names:obligation:maskedProperty');
      result.obligations[0].attributes[0].value.should.equal('urn:restorecommerce:acs:model:location.Location#description');
      // validate 2 rules
      result.policy_sets[0].policies[0].rules.should.be.length(2);
      result.policy_sets[0].policies[0].rules[0].id.should.equal('ruleAA1');
      result.policy_sets[0].policies[0].rules[1].id.should.equal('ruleAA2');
    });
    it('should return empty obligation for AdminUser and filtered rules for Location resource request reading for id, name and description', async (): Promise<void> => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'AdminUser',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceProperty: ['urn:restorecommerce:acs:model:location.Location#id', 'urn:restorecommerce:acs:model:location.Location#name', 'urn:restorecommerce:acs:model:location.Location#description'],
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'SuperOrg1',
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: 'Org1'
      });
      testUtils.marshallRequest(accessRequest);
      const result = await accessControlService.whatIsAllowed(accessRequest);
      should.exist(result);
      // validate obligation
      should.not.exist(result.obligations);
      // validate 2 rules
      result.policy_sets[0].policies[0].rules.should.be.length(1);
      result.policy_sets[0].policies[0].rules[0].id.should.equal('ruleAA3');
    });
    it('should return empty obligation for AdminUser and filtered rules for Location resource with empty properties in request', async (): Promise<void> => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'AdminUser',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'SuperOrg1',
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: 'Org1'
      });
      testUtils.marshallRequest(accessRequest);
      const result = await accessControlService.whatIsAllowed(accessRequest);
      should.exist(result);
      // validate obligation
      should.not.exist(result.obligations);
      // validate 2 rules
      result.policy_sets[0].policies[0].rules.should.be.length(1);
      result.policy_sets[0].policies[0].rules[0].id.should.equal('ruleAA3');
    });
  });

  describe('testing isAllowed with multiple entities and different properties in each entity', () => {
    before(async () => {
      // disable authorization
      cfg.set('authorization:enabled', false);
      cfg.set('authorization:enforce', false);
      updateConfig(cfg);
      await create('./test/fixtures/multiple_entities_with_properties.yml');
    });
    after(async () => {
      await truncate();
    });
    // read - isAllowed - Location and Organization Entity
    it('should PERMIT reading Location and Organization with locid, locname, orgid and orgname properties', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: ['urn:restorecommerce:acs:model:location.Location', 'urn:restorecommerce:acs:model:organization.Organization'],
        resourceProperty: [['urn:restorecommerce:acs:model:location.Location#locid', 'urn:restorecommerce:acs:model:location.Location#locname'],
        ['urn:restorecommerce:acs:model:organization.Organization#orgid', 'urn:restorecommerce:acs:model:organization.Organization#orgname']],
        resourceID: ['Bob', 'Org'],
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: ['Org1', 'Org1']
      });
      testUtils.marshallRequest(accessRequest);

      const result = await accessControlService.isAllowed(accessRequest);
      should.exist(result);
      should.exist(result.decision);
      result.decision.should.equal(Response_Decision.PERMIT);
      result.operation_status.code.should.equal(200);
      result.operation_status.message.should.equal('success');
    });
    it('should PERMIT reading Location and Organization with locid and orgid property', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: ['urn:restorecommerce:acs:model:location.Location', 'urn:restorecommerce:acs:model:organization.Organization'],
        resourceProperty: [['urn:restorecommerce:acs:model:location.Location#locid'], ['urn:restorecommerce:acs:model:organization.Organization#orgid']],
        resourceID: ['Bob', 'Org'],
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: ['Org1', 'Org1']
      });
      testUtils.marshallRequest(accessRequest);

      const result = await accessControlService.isAllowed(accessRequest);
      should.exist(result);
      should.exist(result.decision);
      result.decision.should.equal(Response_Decision.PERMIT);
      result.operation_status.code.should.equal(200);
      result.operation_status.message.should.equal('success');
    });
    it('should DENY reading Location (locid, locname) and Organization (orgid, orgname and orgdescription) since description property not allowed property for Organization', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: ['urn:restorecommerce:acs:model:location.Location', 'urn:restorecommerce:acs:model:organization.Organization'],
        resourceProperty: [['urn:restorecommerce:acs:model:location.Location#locid', 'urn:restorecommerce:acs:model:location.Location#locname'],
        ['urn:restorecommerce:acs:model:organization.Organization#orgid', 'urn:restorecommerce:acs:model:organization.Organization#orgname', 'urn:restorecommerce:acs:model:organization.Organization#orgdescription']],
        resourceID: ['Bob', 'Org'],
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: ['Org1', 'Org1']
      });
      testUtils.marshallRequest(accessRequest);

      const result = await accessControlService.isAllowed(accessRequest);
      should.exist(result);
      should.exist(result.decision);
      result.decision.should.equal(Response_Decision.DENY);
      result.operation_status.code.should.equal(200);
      result.operation_status.message.should.equal('success');
    });
    it('should DENY reading Location when no properties are provided at all (since the properties are defined on Rule)', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: ['urn:restorecommerce:acs:model:location.Location', 'urn:restorecommerce:acs:model:organization.Organization'],
        resourceID: ['Bob', 'Org'],
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: ['Org1', 'Org1']
      });
      testUtils.marshallRequest(accessRequest);

      const result = await accessControlService.isAllowed(accessRequest);
      should.exist(result);
      should.exist(result.decision);
      result.decision.should.equal(Response_Decision.DENY);
      result.operation_status.code.should.equal(200);
      result.operation_status.message.should.equal('success');
    });
    // modify - isAllowed - Location and Organization Entity
    it('should PERMIT modifying Location and Organization with locid, locname, orgid and orgname properties', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: ['urn:restorecommerce:acs:model:location.Location', 'urn:restorecommerce:acs:model:organization.Organization'],
        resourceProperty: [['urn:restorecommerce:acs:model:location.Location#locid', 'urn:restorecommerce:acs:model:location.Location#locname'],
        ['urn:restorecommerce:acs:model:organization.Organization#orgid', 'urn:restorecommerce:acs:model:organization.Organization#orgname']],
        resourceID: ['Bob', 'Org'],
        actionType: 'urn:restorecommerce:acs:names:action:modify',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: ['Org1', 'Org1']
      });
      testUtils.marshallRequest(accessRequest);

      const result = await accessControlService.isAllowed(accessRequest);
      should.exist(result);
      should.exist(result.decision);
      result.decision.should.equal(Response_Decision.PERMIT);
      result.operation_status.code.should.equal(200);
      result.operation_status.message.should.equal('success');
    });
    it('should PERMIT modifying Location and Organization with locid and orgid property', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: ['urn:restorecommerce:acs:model:location.Location', 'urn:restorecommerce:acs:model:organization.Organization'],
        resourceProperty: [['urn:restorecommerce:acs:model:location.Location#locid'], ['urn:restorecommerce:acs:model:organization.Organization#orgid']],
        resourceID: ['Bob', 'Org'],
        actionType: 'urn:restorecommerce:acs:names:action:modify',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: ['Org1', 'Org1']
      });
      testUtils.marshallRequest(accessRequest);

      const result = await accessControlService.isAllowed(accessRequest);
      should.exist(result);
      should.exist(result.decision);
      result.decision.should.equal(Response_Decision.PERMIT);
      result.operation_status.code.should.equal(200);
      result.operation_status.message.should.equal('success');
    });
    it('should DENY modifying Location (locid, locname) and Organization (orgid, orgname and orgdescription) since description property not allowed property for Organization', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: ['urn:restorecommerce:acs:model:location.Location', 'urn:restorecommerce:acs:model:organization.Organization'],
        resourceProperty: [['urn:restorecommerce:acs:model:location.Location#locid', 'urn:restorecommerce:acs:model:location.Location#locname'],
        ['urn:restorecommerce:acs:model:organization.Organization#orgid', 'urn:restorecommerce:acs:model:organization.Organization#orgname', 'urn:restorecommerce:acs:model:organization.Organization#orgdescription']],
        resourceID: ['Bob', 'Org'],
        actionType: 'urn:restorecommerce:acs:names:action:modify',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: ['Org1', 'Org1']
      });
      testUtils.marshallRequest(accessRequest);

      const result = await accessControlService.isAllowed(accessRequest);
      should.exist(result);
      should.exist(result.decision);
      result.decision.should.equal(Response_Decision.DENY);
      result.operation_status.code.should.equal(200);
      result.operation_status.message.should.equal('success');
    });
    it('should DENY modifying Location when no properties are provided at all (since the properties are defined on Rule)', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: ['urn:restorecommerce:acs:model:location.Location', 'urn:restorecommerce:acs:model:organization.Organization'],
        resourceID: ['Bob', 'Org'],
        actionType: 'urn:restorecommerce:acs:names:action:modify',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: ['Org1', 'Org1']
      });
      testUtils.marshallRequest(accessRequest);

      const result = await accessControlService.isAllowed(accessRequest);
      should.exist(result);
      should.exist(result.decision);
      result.decision.should.equal(Response_Decision.DENY);
      result.operation_status.code.should.equal(200);
      result.operation_status.message.should.equal('success');
    });
  });

  describe('testing whatIsAllowed with multiple entities and different properties in each entity', () => {
    before(async () => {
      // disable authorization
      cfg.set('authorization:enabled', false);
      cfg.set('authorization:enforce', false);
      updateConfig(cfg);
      await create('./test/fixtures/multiple_entities_with_properties.yml');
    });
    after(async () => {
      await truncate();
    });
    it('should PERMIT reading Location and Organization with locid, locname, orgid and orgname properties with empty Obligation', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: ['urn:restorecommerce:acs:model:location.Location', 'urn:restorecommerce:acs:model:organization.Organization'],
        resourceProperty: [['urn:restorecommerce:acs:model:location.Location#locid', 'urn:restorecommerce:acs:model:location.Location#locname'],
        ['urn:restorecommerce:acs:model:organization.Organization#orgid', 'urn:restorecommerce:acs:model:organization.Organization#orgname']],
        resourceID: ['Bob', 'Org'],
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: ['Org1', 'Org1']
      });
      testUtils.marshallRequest(accessRequest);

      const result = await accessControlService.whatIsAllowed(accessRequest);
      // validate obligation
      should.not.exist(result.obligations);
      // validate policies
      result.policy_sets[0].policies.should.be.length(2);
      result.policy_sets[0].policies[0].id.should.equal('LocationPolicy');
      result.policy_sets[0].policies[1].id.should.equal('OrganizationPolicy');
      // validate location rules
      result.policy_sets[0].policies[0].rules.should.be.length(2);
      result.policy_sets[0].policies[0].rules[0].id.should.equal('ruleAA1');
      result.policy_sets[0].policies[0].rules[1].id.should.equal('ruleAA3');
      // validate organization rules
      result.policy_sets[0].policies[1].rules.should.be.length(2);
      result.policy_sets[0].policies[1].rules[0].id.should.equal('ruleAA4');
      result.policy_sets[0].policies[1].rules[1].id.should.equal('ruleAA6');
    });
    it('should PERMIT reading Location and Organization with locid and orgid properties with empty obligation', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: ['urn:restorecommerce:acs:model:location.Location', 'urn:restorecommerce:acs:model:organization.Organization'],
        resourceProperty: [['urn:restorecommerce:acs:model:location.Location#locid'], ['urn:restorecommerce:acs:model:organization.Organization#orgid']],
        resourceID: ['Bob', 'Org'],
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: ['Org1', 'Org1']
      });
      testUtils.marshallRequest(accessRequest);

      const result = await accessControlService.whatIsAllowed(accessRequest);
      // validate obligation
      should.not.exist(result.obligations);
      // validate policies
      result.policy_sets[0].policies.should.be.length(2);
      result.policy_sets[0].policies[0].id.should.equal('LocationPolicy');
      result.policy_sets[0].policies[1].id.should.equal('OrganizationPolicy');
      // validate location rules
      result.policy_sets[0].policies[0].rules.should.be.length(2);
      result.policy_sets[0].policies[0].rules[0].id.should.equal('ruleAA1');
      result.policy_sets[0].policies[0].rules[1].id.should.equal('ruleAA3');
      // validate organization rules
      result.policy_sets[0].policies[1].rules.should.be.length(2);
      result.policy_sets[0].policies[1].rules[0].id.should.equal('ruleAA4');
      result.policy_sets[0].policies[1].rules[1].id.should.equal('ruleAA6');
    });
    it('should PERMIT reading Location (locid, locname) and Organization (orgid, orgname and orgdescription) with Obligation for orgdescription property', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: ['urn:restorecommerce:acs:model:location.Location', 'urn:restorecommerce:acs:model:organization.Organization'],
        resourceProperty: [['urn:restorecommerce:acs:model:location.Location#locid', 'urn:restorecommerce:acs:model:location.Location#locname', 'urn:restorecommerce:acs:model:location.Location#locdescription'],
        ['urn:restorecommerce:acs:model:organization.Organization#orgid', 'urn:restorecommerce:acs:model:organization.Organization#orgname', 'urn:restorecommerce:acs:model:organization.Organization#orgdescription']],
        resourceID: ['Bob', 'Org'],
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: ['Org1', 'Org1']
      });
      testUtils.marshallRequest(accessRequest);

      const result = await accessControlService.whatIsAllowed(accessRequest);
      // validate location obligation
      result.obligations.should.be.length(2);
      result.obligations[0].id.should.equal('urn:restorecommerce:acs:names:model:entity');
      result.obligations[0].value.should.equal('urn:restorecommerce:acs:model:location.Location');
      result.obligations[0].attributes[0].id.should.equal('urn:restorecommerce:acs:names:obligation:maskedProperty');
      result.obligations[0].attributes[0].value.should.equal('urn:restorecommerce:acs:model:location.Location#locdescription');
      // validate organization obligation
      result.obligations[1].id.should.equal('urn:restorecommerce:acs:names:model:entity');
      result.obligations[1].value.should.equal('urn:restorecommerce:acs:model:organization.Organization');
      result.obligations[1].attributes[0].id.should.equal('urn:restorecommerce:acs:names:obligation:maskedProperty');
      result.obligations[1].attributes[0].value.should.equal('urn:restorecommerce:acs:model:organization.Organization#orgdescription');

      // validate policies
      result.policy_sets[0].policies.should.be.length(2);
      result.policy_sets[0].policies[0].id.should.equal('LocationPolicy');
      result.policy_sets[0].policies[1].id.should.equal('OrganizationPolicy');
      // validate location rules
      result.policy_sets[0].policies[0].rules.should.be.length(2);
      result.policy_sets[0].policies[0].rules[0].id.should.equal('ruleAA1');
      result.policy_sets[0].policies[0].rules[1].id.should.equal('ruleAA3');
      // validate organization rules
      result.policy_sets[0].policies[1].rules.should.be.length(2);
      result.policy_sets[0].policies[1].rules[0].id.should.equal('ruleAA4');
      result.policy_sets[0].policies[1].rules[1].id.should.equal('ruleAA6');
    });
    it('should return only DENY rules for reading Location and Organization when no properties are provided at all (since the properties are defined on Rule)', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: ['urn:restorecommerce:acs:model:location.Location', 'urn:restorecommerce:acs:model:organization.Organization'],
        resourceID: ['Bob', 'Org'],
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: ['Org1', 'Org1']
      });
      testUtils.marshallRequest(accessRequest);

      const result = await accessControlService.whatIsAllowed(accessRequest);
      // validate obligation
      should.not.exist(result.obligations);
      // validate policies
      result.policy_sets[0].policies.should.be.length(2);
      result.policy_sets[0].policies[0].id.should.equal('LocationPolicy');
      result.policy_sets[0].policies[1].id.should.equal('OrganizationPolicy');
      // validate location rules
      result.policy_sets[0].policies[0].rules.should.be.length(1);
      result.policy_sets[0].policies[0].rules[0].id.should.equal('ruleAA3');
      // validate organization rules
      result.policy_sets[0].policies[1].rules.should.be.length(1);
      result.policy_sets[0].policies[1].rules[0].id.should.equal('ruleAA6');
    });
  });

  describe('testing isAllowed with multiple entities with multiple rules for each entity', () => {
    before(async () => {
      // disable authorization
      cfg.set('authorization:enabled', false);
      cfg.set('authorization:enforce', false);
      updateConfig(cfg);
      await create('./test/fixtures/multiple_rules_multiple_entities_with_properties.yml');
    });
    after(async () => {
      await truncate();
    });
    // read - isAllowed - Location and Organization Entity with multiple rules for each entity
    it('should PERMIT reading Location and Organization with locid, locname, orgid and orgname properties', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: ['urn:restorecommerce:acs:model:location.Location', 'urn:restorecommerce:acs:model:organization.Organization'],
        resourceProperty: [['urn:restorecommerce:acs:model:location.Location#locid', 'urn:restorecommerce:acs:model:location.Location#locname'],
        ['urn:restorecommerce:acs:model:organization.Organization#orgid', 'urn:restorecommerce:acs:model:organization.Organization#orgname']],
        resourceID: ['Bob', 'Org'],
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: ['Org1', 'Org1']
      });
      testUtils.marshallRequest(accessRequest);

      const result = await accessControlService.isAllowed(accessRequest);
      should.exist(result);
      should.exist(result.decision);
      result.decision.should.equal(Response_Decision.PERMIT);
      result.operation_status.code.should.equal(200);
      result.operation_status.message.should.equal('success');
    });
    it('should DENY reading Location and Organization with locid, locname, orgid and orgname and orgdescription properties (orgdescription not allowed)', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: ['urn:restorecommerce:acs:model:location.Location', 'urn:restorecommerce:acs:model:organization.Organization'],
        resourceProperty: [['urn:restorecommerce:acs:model:location.Location#locid', 'urn:restorecommerce:acs:model:location.Location#locname'],
        ['urn:restorecommerce:acs:model:organization.Organization#orgid', 'urn:restorecommerce:acs:model:organization.Organization#orgname', 'urn:restorecommerce:acs:model:organization.Organization#orgdescription']],
        resourceID: ['Bob', 'Org'],
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: ['Org1', 'Org1']
      });
      testUtils.marshallRequest(accessRequest);

      const result = await accessControlService.isAllowed(accessRequest);
      should.exist(result);
      should.exist(result.decision);
      result.decision.should.equal(Response_Decision.DENY);
      result.operation_status.code.should.equal(200);
      result.operation_status.message.should.equal('success');
    });
    it('should DENY reading Location and Organization with no properties (due to DENY rule not allowed as we do not know what properties subject would read)', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: ['urn:restorecommerce:acs:model:location.Location', 'urn:restorecommerce:acs:model:organization.Organization'],
        resourceID: ['Bob', 'Org'],
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: ['Org1', 'Org1']
      });
      testUtils.marshallRequest(accessRequest);

      const result = await accessControlService.isAllowed(accessRequest);
      should.exist(result);
      should.exist(result.decision);
      result.decision.should.equal(Response_Decision.DENY);
      result.operation_status.code.should.equal(200);
      result.operation_status.message.should.equal('success');
    });
  });
  describe('testing whatIsAllowed with multiple entities with multiple rules for each entity', () => {
    before(async () => {
      // disable authorization
      cfg.set('authorization:enabled', false);
      cfg.set('authorization:enforce', false);
      updateConfig(cfg);
      await create('./test/fixtures/multiple_rules_multiple_entities_with_properties.yml');
    });
    after(async () => {
      await truncate();
    });
    // read - isAllowed - Location and Organization Entity with multiple rules for each entity
    it('should PERMIT reading Location and Organization with locid, locname, orgid and orgname properties with empty obligation', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: ['urn:restorecommerce:acs:model:location.Location', 'urn:restorecommerce:acs:model:organization.Organization'],
        resourceProperty: [['urn:restorecommerce:acs:model:location.Location#locid', 'urn:restorecommerce:acs:model:location.Location#locname'],
        ['urn:restorecommerce:acs:model:organization.Organization#orgid', 'urn:restorecommerce:acs:model:organization.Organization#orgname']],
        resourceID: ['Bob', 'Org'],
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: ['Org1', 'Org1']
      });
      testUtils.marshallRequest(accessRequest);

      const result = await accessControlService.whatIsAllowed(accessRequest);
      // validate obligation
      should.not.exist(result.obligations);
      // validate location rules
      result.policy_sets[0].policies[0].rules.should.be.length(2);
      result.policy_sets[0].policies[0].rules[0].id.should.equal('ruleAA1');
      result.policy_sets[0].policies[0].rules[1].id.should.equal('ruleAA2');
      // validate organization rules
      result.policy_sets[0].policies[1].rules.should.be.length(2);
      result.policy_sets[0].policies[1].rules[0].id.should.equal('ruleAA3');
      result.policy_sets[0].policies[1].rules[1].id.should.equal('ruleAA4');
    });
    it('should PERMIT reading Location and Organization with locid, locname, orgid and orgname and orgdescription properties with orgdescription in obligation', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: ['urn:restorecommerce:acs:model:location.Location', 'urn:restorecommerce:acs:model:organization.Organization'],
        resourceProperty: [['urn:restorecommerce:acs:model:location.Location#locid', 'urn:restorecommerce:acs:model:location.Location#locname'],
        ['urn:restorecommerce:acs:model:organization.Organization#orgid', 'urn:restorecommerce:acs:model:organization.Organization#orgname', 'urn:restorecommerce:acs:model:organization.Organization#orgdescription']],
        resourceID: ['Bob', 'Org'],
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: ['Org1', 'Org1']
      });
      testUtils.marshallRequest(accessRequest);

      const result = await accessControlService.whatIsAllowed(accessRequest);
      // validate obligation for organization resource
      result.obligations.should.be.length(1);
      result.obligations[0].id.should.equal('urn:restorecommerce:acs:names:model:entity');
      result.obligations[0].value.should.equal('urn:restorecommerce:acs:model:organization.Organization');
      result.obligations[0].attributes[0].id.should.equal('urn:restorecommerce:acs:names:obligation:maskedProperty');
      result.obligations[0].attributes[0].value.should.equal('urn:restorecommerce:acs:model:organization.Organization#orgdescription');
      // validate location rules
      result.policy_sets[0].policies[0].rules.should.be.length(2);
      result.policy_sets[0].policies[0].rules[0].id.should.equal('ruleAA1');
      result.policy_sets[0].policies[0].rules[1].id.should.equal('ruleAA2');
      // validate organization rules
      result.policy_sets[0].policies[1].rules.should.be.length(2);
      result.policy_sets[0].policies[1].rules[0].id.should.equal('ruleAA3');
      result.policy_sets[0].policies[1].rules[1].id.should.equal('ruleAA4');
    });
    it('should PERMIT reading Location and Organization with no properties with obligation for locdescription and orgdescription (since subject has PERMIT for everything and DENY for these two props)', async () => {
      const accessRequest = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: ['urn:restorecommerce:acs:model:location.Location', 'urn:restorecommerce:acs:model:organization.Organization'],
        resourceID: ['Bob', 'Org'],
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: ['Org1', 'Org1']
      });
      testUtils.marshallRequest(accessRequest);

      const result = await accessControlService.whatIsAllowed(accessRequest);
      // validate obligation for location resource
      result.obligations.should.be.length(2);
      result.obligations[0].id.should.equal('urn:restorecommerce:acs:names:model:entity');
      result.obligations[0].value.should.equal('urn:restorecommerce:acs:model:location.Location');
      result.obligations[0].attributes[0].id.should.equal('urn:restorecommerce:acs:names:obligation:maskedProperty');
      result.obligations[0].attributes[0].value.should.equal('urn:restorecommerce:acs:model:location.Location#locdescription');
      // validate obligation for organization resource
      result.obligations[1].id.should.equal('urn:restorecommerce:acs:names:model:entity');
      result.obligations[1].value.should.equal('urn:restorecommerce:acs:model:organization.Organization');
      result.obligations[1].attributes[0].id.should.equal('urn:restorecommerce:acs:names:obligation:maskedProperty');
      result.obligations[1].attributes[0].value.should.equal('urn:restorecommerce:acs:model:organization.Organization#orgdescription');
      // validate location rules
      result.policy_sets[0].policies[0].rules.should.be.length(2);
      result.policy_sets[0].policies[0].rules[0].id.should.equal('ruleAA1');
      result.policy_sets[0].policies[0].rules[1].id.should.equal('ruleAA2');
      // validate organization rules
      result.policy_sets[0].policies[1].rules.should.be.length(2);
      result.policy_sets[0].policies[1].rules[0].id.should.equal('ruleAA3');
      result.policy_sets[0].policies[1].rules[1].id.should.equal('ruleAA4');
    });
  });
});