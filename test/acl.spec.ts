import should from 'should';
import { Worker } from '../src/worker';
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


describe('testing ACL for microservice', () => {
  describe('testing access-control-list', () => {
    before(async () => {
      await setupService();
    });
    after(async () => {
      await worker.stop();
    });
    describe('isAllowed()', () => {
      before(async () => {
        // disable authorization to import rules
        cfg.set('authorization:enabled', false);
        cfg.set('authorization:enforce', false);
        updateConfig(cfg);
        await create('./test/fixtures/acl_policies.yml');
        // enable authorization after importing rules
        cfg.set('authorization:enabled', false);
        cfg.set('authorization:enforce', false);
        updateConfig(cfg);
      });
      after(async function (): Promise<void> {
        this.timeout(5000);
        await truncate();
      });
      it('should PERMIT creating bucket resource with valid ACL instances', async () => {
        const accessRequest = testUtils.buildRequest({
          subjectID: 'Alice',
          subjectRole: 'Admin',
          roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          roleScopingInstance: 'SuperOrg1',
          resourceType: 'urn:restorecommerce:acs:model:bucket.Bucket',
          resourceID: 'test',
          actionType: 'urn:restorecommerce:acs:names:action:create',
          ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          ownerInstance: 'SuperOrg1',
          aclIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          aclInstances: ['Org1', 'Org2', 'Org3']
        });
        testUtils.marshallRequest(accessRequest);
        const result = await accessControlService.isAllowed(accessRequest);
        should.exist(result);
        should.exist(result.decision);
        should.equal(result.decision, Response_Decision.PERMIT);
      });

      it('should DENY creating bucket resource with invalid ACL instances', async () => {
        const accessRequest = testUtils.buildRequest({
          subjectID: 'Alice',
          subjectRole: 'Admin',
          roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          roleScopingInstance: 'SuperOrg1',
          resourceType: 'urn:restorecommerce:acs:model:bucket.Bucket',
          resourceID: 'test',
          actionType: 'urn:restorecommerce:acs:names:action:create',
          ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          ownerInstance: 'SuperOrg1',
          aclIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          aclInstances: ['Org1', 'Org4'] // Org4 is invalid as its not present in user HR
        });
        testUtils.marshallRequest(accessRequest);
        const result = await accessControlService.isAllowed(accessRequest);
        should.exist(result);
        should.exist(result.decision);
        should.equal(result.decision, Response_Decision.DENY);
      });

      it('should PERMIT creating bucket resource with SubjectID ACL instances', async () => {
        const accessRequest = testUtils.buildRequest({
          subjectID: 'Alice',
          subjectRole: 'Admin',
          roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          roleScopingInstance: 'SuperOrg1',
          resourceType: 'urn:restorecommerce:acs:model:bucket.Bucket',
          resourceID: 'test',
          actionType: 'urn:restorecommerce:acs:names:action:create',
          ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          ownerInstance: 'SuperOrg1',
          aclIndicatoryEntity: 'urn:restorecommerce:acs:model:user.User',
          aclInstances: ['SubjectID1', 'SubjectID2'] // subjectIDs are currently not validted and Permit
        });
        testUtils.marshallRequest(accessRequest);
        const result = await accessControlService.isAllowed(accessRequest);
        should.exist(result);
        should.exist(result.decision);
        should.equal(result.decision, Response_Decision.PERMIT);
      });

      it('should PERMIT creating bucket resource with SubjectID ACL instances and valid Org Instances', async () => {
        const accessRequest = testUtils.buildRequest({
          subjectID: 'Alice',
          subjectRole: 'Admin',
          roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          roleScopingInstance: 'SuperOrg1',
          resourceType: 'urn:restorecommerce:acs:model:bucket.Bucket',
          resourceID: 'test',
          actionType: 'urn:restorecommerce:acs:names:action:create',
          ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          ownerInstance: 'SuperOrg1',
          multipleAclIndicatoryEntity: ['urn:restorecommerce:acs:model:organization.Organization', 'urn:restorecommerce:acs:model:user.User'],
          orgInstances: ['Org1', 'Org2', 'Org3'],
          subjectInstances: ['SubjectID1', 'SubjectID2']
        });
        testUtils.marshallRequest(accessRequest);
        const result = await accessControlService.isAllowed(accessRequest);
        should.exist(result);
        should.exist(result.decision);
        should.equal(result.decision, Response_Decision.PERMIT);
      });

      it('should DENY creating bucket resource with SubjectID ACL instances and Invalid Org Instances', async () => {
        const accessRequest = testUtils.buildRequest({
          subjectID: 'Alice',
          subjectRole: 'Admin',
          roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          roleScopingInstance: 'SuperOrg1',
          resourceType: 'urn:restorecommerce:acs:model:bucket.Bucket',
          resourceID: 'test',
          actionType: 'urn:restorecommerce:acs:names:action:create',
          ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          ownerInstance: 'SuperOrg1',
          multipleAclIndicatoryEntity: ['urn:restorecommerce:acs:model:organization.Organization', 'urn:restorecommerce:acs:model:user.User'],
          orgInstances: ['Org1', 'Org4'], // Org4 is invalid as its not present in user HR
          subjectInstances: ['SubjectID1', 'SubjectID2']
        });
        testUtils.marshallRequest(accessRequest);
        const result = await accessControlService.isAllowed(accessRequest);
        should.exist(result);
        should.exist(result.decision);
        should.equal(result.decision, Response_Decision.DENY);
      });

      it('should PERMIT modifying bucket resource with reduced valid ACL instances', async () => {
        const accessRequest = testUtils.buildRequest({
          subjectID: 'Alice',
          subjectRole: 'Admin',
          roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          roleScopingInstance: 'Org1',
          resourceType: 'urn:restorecommerce:acs:model:bucket.Bucket',
          resourceID: 'test',
          actionType: 'urn:restorecommerce:acs:names:action:modify',
          ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          ownerInstance: 'Org1',
          aclIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          aclInstances: ['Org1']
        });
        testUtils.marshallRequest(accessRequest);
        const result = await accessControlService.isAllowed(accessRequest);
        should.exist(result);
        should.exist(result.decision);
        should.equal(result.decision, Response_Decision.PERMIT);
      });

      it('should PERMIT modifying bucket resource with valid ACL and subject instances', async () => {
        const accessRequest = testUtils.buildRequest({
          subjectID: 'Alice',
          subjectRole: 'Admin',
          roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          roleScopingInstance: 'Org4', // although he has invalidOrg he has the subjectID in ACL and hence valid request for modify
          resourceType: 'urn:restorecommerce:acs:model:bucket.Bucket',
          resourceID: 'test',
          actionType: 'urn:restorecommerce:acs:names:action:modify',
          ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          ownerInstance: 'Org4',
          multipleAclIndicatoryEntity: ['urn:restorecommerce:acs:model:organization.Organization', 'urn:restorecommerce:acs:model:user.User'],
          orgInstances: ['Org1', 'Org2'],
          subjectInstances: ['SubjectID1', 'Alice']
        });
        testUtils.marshallRequest(accessRequest);
        const result = await accessControlService.isAllowed(accessRequest);
        should.exist(result);
        should.exist(result.decision);
        should.equal(result.decision, Response_Decision.PERMIT);
      });

      it('should DENY modifying bucket resource with invalid ACL instances', async () => {
        const accessRequest = testUtils.buildRequest({
          subjectID: 'Alice',
          subjectRole: 'Admin',
          roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          roleScopingInstance: 'SuperOrg1',
          resourceType: 'urn:restorecommerce:acs:model:bucket.Bucket',
          resourceID: 'test',
          actionType: 'urn:restorecommerce:acs:names:action:modify',
          ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          ownerInstance: 'SuperOrg1',
          aclIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          aclInstances: ['Org1', 'Org4'] // Org4 is invalid as its not present in user HR
        });
        testUtils.marshallRequest(accessRequest);
        const result = await accessControlService.isAllowed(accessRequest);
        should.exist(result);
        should.exist(result.decision);
        should.equal(result.decision, Response_Decision.DENY);
      });

      it('should PERMIT deleting bucket resource with valid ACL instances', async () => {
        const accessRequest = testUtils.buildRequest({
          subjectID: 'Alice',
          subjectRole: 'Admin',
          roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          roleScopingInstance: 'Org1',
          resourceType: 'urn:restorecommerce:acs:model:bucket.Bucket',
          resourceID: 'test',
          actionType: 'urn:restorecommerce:acs:names:action:delete',
          ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          ownerInstance: 'Org1',
          aclIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          aclInstances: ['Org1', 'Org2']
        });
        testUtils.marshallRequest(accessRequest);
        const result = await accessControlService.isAllowed(accessRequest);
        should.exist(result);
        should.exist(result.decision);
        should.equal(result.decision, Response_Decision.PERMIT);
      });

      it('should PERMIT deleting bucket resource with valid subject instance', async () => {
        const accessRequest = testUtils.buildRequest({
          subjectID: 'Alice',
          subjectRole: 'Admin',
          roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          roleScopingInstance: 'Org4', // although Org4 is not present in ACL, its PERMIT because of subjectID in ACL
          resourceType: 'urn:restorecommerce:acs:model:bucket.Bucket',
          resourceID: 'test',
          actionType: 'urn:restorecommerce:acs:names:action:delete',
          ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          ownerInstance: 'Org4',
          multipleAclIndicatoryEntity: ['urn:restorecommerce:acs:model:organization.Organization', 'urn:restorecommerce:acs:model:user.User'],
          orgInstances: ['Org1', 'Org2'],
          subjectInstances: ['SubjectID1', 'Alice']
        });
        testUtils.marshallRequest(accessRequest);
        const result = await accessControlService.isAllowed(accessRequest);
        should.exist(result);
        should.exist(result.decision);
        should.equal(result.decision, Response_Decision.PERMIT);
      });

      it('should DENY deleting bucket resource with no valid scope or subject id in ACL', async () => {
        const accessRequest = testUtils.buildRequest({
          subjectID: 'Alice',
          subjectRole: 'Admin',
          roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          roleScopingInstance: 'Org4', // Org4 is not present in ACL and also subject Alice, its DENY
          resourceType: 'urn:restorecommerce:acs:model:bucket.Bucket',
          resourceID: 'test',
          actionType: 'urn:restorecommerce:acs:names:action:delete',
          ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          ownerInstance: 'Org4',
          multipleAclIndicatoryEntity: ['urn:restorecommerce:acs:model:organization.Organization', 'urn:restorecommerce:acs:model:user.User'],
          orgInstances: ['Org1', 'Org2'],
          subjectInstances: ['SubjectID1']
        });
        testUtils.marshallRequest(accessRequest);
        const result = await accessControlService.isAllowed(accessRequest);
        should.exist(result);
        should.exist(result.decision);
        should.equal(result.decision, Response_Decision.DENY);
      });

      it('should PERMIT reading bucket resource by SimpleUser role (valid ACL List)', async () => {
        const accessRequest = testUtils.buildRequest({
          subjectID: 'Alice',
          subjectRole: 'SimpleUser',
          roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          roleScopingInstance: 'Org1',
          resourceType: 'urn:restorecommerce:acs:model:bucket.Bucket',
          resourceID: 'test',
          actionType: 'urn:restorecommerce:acs:names:action:read',
          ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          ownerInstance: 'Org1',
          aclIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          aclInstances: ['Org1', 'Org2', 'Org3']
        });
        testUtils.marshallRequest(accessRequest);
        const result = await accessControlService.isAllowed(accessRequest);
        should.exist(result);
        should.exist(result.decision);
        should.equal(result.decision, Response_Decision.PERMIT);
      });

      it('should PERMIT reading bucket resource by SimpleUser role (ACL list contains valid subjectID)', async () => {
        const accessRequest = testUtils.buildRequest({
          subjectID: 'Alice',
          subjectRole: 'SimpleUser',
          roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          roleScopingInstance: 'Org4', // role is scoped on Org4, but should be PERMIT as subject Alice is present in ACL
          resourceType: 'urn:restorecommerce:acs:model:bucket.Bucket',
          resourceID: 'test',
          actionType: 'urn:restorecommerce:acs:names:action:read',
          ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          ownerInstance: 'Org4',
          multipleAclIndicatoryEntity: ['urn:restorecommerce:acs:model:organization.Organization', 'urn:restorecommerce:acs:model:user.User'],
          orgInstances: ['Org1', 'Org2'],
          subjectInstances: ['SubjectID1', 'Alice']
        });
        testUtils.marshallRequest(accessRequest);
        const result = await accessControlService.isAllowed(accessRequest);
        should.exist(result);
        should.exist(result.decision);
        should.equal(result.decision, Response_Decision.PERMIT);
      });

      it('should DENY reading bucket resource by SimpleUser role (ACL list does not contain target role scope)', async () => {
        const accessRequest = testUtils.buildRequest({
          subjectID: 'Alice',
          subjectRole: 'SimpleUser',
          roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          roleScopingInstance: 'Org4', // role is scoped on Org4
          resourceType: 'urn:restorecommerce:acs:model:bucket.Bucket',
          resourceID: 'test',
          actionType: 'urn:restorecommerce:acs:names:action:read',
          ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          ownerInstance: 'Org1',
          aclIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
          aclInstances: ['Org1', 'Org2', 'Org3']
        });
        testUtils.marshallRequest(accessRequest);
        const result = await accessControlService.isAllowed(accessRequest);
        should.exist(result);
        should.exist(result.decision);
        should.equal(result.decision, Response_Decision.DENY);
      });
    });
  });
});