import * as mocha from 'mocha';
import * as should from 'should';

import * as core from '../lib/core';
import { Worker } from '../lib/worker';
import * as testUtils from './utils';

import { createServiceConfig } from '@restorecommerce/service-config';
import { createLogger } from '@restorecommerce/logger';
import { Client } from '@restorecommerce/grpc-client';

import * as yaml from 'js-yaml';
import * as fs from 'fs';
import { updateConfig } from '@restorecommerce/acs-client';

let cfg: any;
let logger;
let client: Client;
let worker: Worker;
let ruleService: any, policyService: any, policySetService: any;
let accessControlService: any;
let rules, policies, policySets;

describe('testing ACL for microservice', () => {
  describe('testing access-control-list', () => {
    before(async () => {
      await setupService();
    });
    after(async () => {
      await client.end();
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
      it('should PERMIT creating bucket resource with valid ACS instances', async () => {

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
          aclInstances: ['SuperOrg1', 'Org1']
        });
        console.log('AccessRequest is....', JSON.stringify(accessRequest));
        testUtils.marshallRequest(accessRequest);

        const result = await accessControlService.isAllowed(accessRequest);
        console.log('Respnose is.........', result);
        // should.exist(result);
        // should.not.exist(result.error);
        // should.exist(result.data);
        // should.exist(result.data.decision);
        // result.data.decision.should.equal(core.Decision.PERMIT);
      });

     
    });
    // describe('testing whatIsAllowed', () => {
    //   before(async () => {
    //     await create('./test/fixtures/acl_policies.yml');
    //   });
    //   after(async () => {
    //     await truncate();
    //   });
    // });
  });
});


async function setupService(): Promise<void> {
  cfg = createServiceConfig(process.cwd() + '/test');
  logger = createLogger(cfg.get('logger'));

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
  const yamlPolicies = yaml.load(fs.readFileSync(policiesFile));
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
