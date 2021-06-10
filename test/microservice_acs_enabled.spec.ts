import * as should from 'should';
import { Worker } from '../src/worker';
import * as testUtils from './utils';

import { createServiceConfig } from '@restorecommerce/service-config';
import { createLogger } from '@restorecommerce/logger';
import { Client } from '@restorecommerce/grpc-client';

import * as yaml from 'js-yaml';
import * as fs from 'fs';
import { updateConfig } from '@restorecommerce/acs-client';
import { createMockServer } from 'grpc-mock';
import { Topic, Events } from '@restorecommerce/kafka-client';

let cfg: any;
let logger;
let client: Client;
let worker: Worker;
let ruleService: any, policyService: any, policySetService: any;
let accessControlService: any;
let rules, policies, policySets;
let mockServer: any;
let userTopic: Topic;

// Admin of mainOrg -> A -> B -> C
let subject = {
  id: 'admin_user_id',
  scope: 'orgC',
  token: 'admin_token',
  role_associations: [
    {
      role: 'admin-r-id',
      attributes: [{
        id: 'urn:restorecommerce:acs:names:roleScopingEntity',
        value: 'urn:restorecommerce:acs:model:organization.Organization'
      },
      {
        id: 'urn:restorecommerce:acs:names:roleScopingInstance',
        value: 'mainOrg'
      }]
    }
  ],
  hierarchical_scopes: [
    {
      id: 'mainOrg',
      role: 'admin-r-id',
      children: [{
        id: 'orgA',
        children: [{
          id: 'orgB',
          children: [{
            id: 'orgC'
          }]
        }]
      }]
    }
  ]
};

let testRule = [{
  id: 'test_rule_id',
  name: 'test rule for test entitiy',
  description: 'test rule',
  target: {
    subject: {
      id: 'urn:oasis:names:tc:xacml:1.0:subject:subject-id',
      value: 'test-r-id'
    },
    resources: {
      id: 'urn:restorecommerce:acs:names:model:entity',
      value: 'urn:restorecommerce:acs:model:test.Test'
    }
  },
  effect: 'PERMIT'
}];

interface serverRule {
  method: string,
  input: any,
  output: any
}

const user = {
  id: subject.id,
  tokens: [{ token: subject.token }],
  role_associations: subject.role_associations
};

// Mock server for ids - findByToken
const startGrpcMockServer = async (rules: serverRule[]) => {
  // Create a mock ACS server to expose isAllowed and whatIsAllowed
  mockServer = createMockServer({
    protoPath: 'test/protos/io/restorecommerce/user.proto',
    packageName: 'io.restorecommerce.user',
    serviceName: 'Service',
    options: {
      keepCase: true
    },
    rules
  });
  mockServer.listen('0.0.0.0:50052');
  logger.info('Identity Server started on port 50052');
};

const stopGrpcMockServer = async () => {
  await mockServer.close(() => {
    logger.info('Server closed successfully');
  });
};

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

async function truncate(): Promise<void> {
  // disable authorization
  cfg.set('authorization:enabled', false);
  cfg.set('authorization:enforce', false);
  updateConfig(cfg);
  await policySetService.delete({
    collection: true,
    subject
  });
  await policyService.delete({
    collection: true,
    subject
  });
  await ruleService.delete({
    collection: true,
    subject
  });
}

// mock to emit back hierarchicalScopesResponse
const hrScopeReqListener = (msg) => {
  const token = msg.token.split(':')[0];
  if (token === 'admin_token') {
    const hrScopeResponse = {
      subject_id: 'admin_user_id',
      token: msg.token,
      hierarchical_scopes: subject.hierarchical_scopes
    };
    userTopic.emit('hierarchicalScopesResponse', hrScopeResponse);
  } else if (token === 'user_token') {
    const hrScopeResponse = {
      subject_id: 'user_id',
      token: msg.token,
      hierarchical_scopes: subject.hierarchical_scopes
    };
    userTopic.emit('hierarchicalScopesResponse', hrScopeResponse);
  }
}

describe('testing microservice', () => {
  describe('testing resource ownership with ACS Enabled', () => {
    before(async () => {
      await setupService();
      await load('./test/fixtures/default_policies.yml');
      // Add a HR scopeReq listener and send back HR scope response
      // to imitate mock from service which is responsible for creating HR scopes
      const events = new Events(cfg.get('events:kafka'), logger);
      await events.start();
      userTopic = await events.topic(cfg.get('events:kafka:topics:user:topic'));
      userTopic.on('hierarchicalScopesRequest', hrScopeReqListener);
    });
    after(async () => {
      // stop mock ids-srv
      stopGrpcMockServer();
      await userTopic.removeAllListeners('hierarchicalScopesRequest');
      await truncate();
      await client.end();
      await worker.stop();
    });
    describe('testing create() operations', () => {
      it('it should insert default rules, policies and policy sets with ACS disabled', async () => {
        // disable authorization
        cfg.set('authorization:enabled', false);
        cfg.set('authorization:enforce', false);
        updateConfig(cfg);
        let result = await policySetService.create({
          items: policySets,
          subject
        });
        should.exist(result.data);
        should.exist(result.data.items);
        result.data.items.should.be.length(policySets.length);
        result = await policyService.create({
          items: policies,
          subject
        });
        should.exist(result.data);
        should.exist(result.data.items);
        result.data.items.should.be.length(policies.length);
        result = await ruleService.create({
          items: rules,
          subject
        });
        should.exist(result.data);
        should.exist(result.data.items);
        result.data.items.should.be.length(rules.length);
      });

      it('should allow to create test rule with ACS enabled with valid scope in subject', async () => {
        const user = {
          id: 'admin_user_id',
          tokens: [{ token: 'admin_token' }],
          role_associations: subject.role_associations
        };
        // start mock ids-srv needed for findByToken response and return subject
        await startGrpcMockServer([{ method: 'findByToken', input: '\{.*\:.*\}', output: user }]);
        await new Promise(r => setTimeout(r, 1000));
        // enable authorization
        cfg.set('authorization:enabled', true);
        cfg.set('authorization:enforce', true);
        updateConfig(cfg);
        const result = await ruleService.create({
          items: testRule,
          subject
        });
        should.exist(result);
        should.not.exist(result.error);
        should.exist(result.data);
        should.exist(result.data.items);
        result.data.items.should.be.length(testRule.length);
      });

      it('should throw an error when trying to create rule with invalid subject scope', async () => {
        // change subject to normal user
        subject.id = 'user_id';
        subject.role_associations[0].role = 'user-r-id';
        subject.token = 'user_token';
        const user = {
          id: subject.id,
          tokens: [{ token: 'user_token' }],
          role_associations: subject.role_associations
        };
        stopGrpcMockServer();
        // restart grpcMock with normal user id
        startGrpcMockServer([{ method: 'findByToken', input: '\{.*\:.*\}', output: user }]);
        const result = await ruleService.create({
          items: testRule,
          subject
        });
        should.exist(result);
        should.not.exist(result.dta);
        should.exist(result.error);
        should.exist(result.error.details);
        result.error.details.should.equal('7 PERMISSION_DENIED: Access not allowed for request with subject:user_id, resource:rule, action:CREATE, target_scope:orgC; the response was DENY');
      });

      it('should allow to update rule with valid subject scope', async () => {
        // change subject to admin user
        subject.id = 'admin_user_id';
        subject.role_associations[0].role = 'admin-r-id';
        subject.token = 'admin_token';
        const user = {
          id: subject.id,
          tokens: [{ token: 'admin_token' }],
          role_associations: subject.role_associations
        };
        stopGrpcMockServer();
        // restart grpcMock with admin user id
        startGrpcMockServer([{ method: 'findByToken', input: '\{.*\:.*\}', output: user }]);
        testRule[0].name = 'modified test rule for test entitiy';
        const result = await ruleService.update({
          items: testRule,
          subject
        });
        should.exist(result.data.items);
        result.data.items[0].name.should.equal('modified test rule for test entitiy');
      });

      it('should not allow to update rule with invalid subject scope', async () => {
        // change subject to normal user
        subject.id = 'user_id';
        subject.role_associations[0].role = 'user-r-id';
        subject.token = 'user_token';
        const user = {
          id: subject.id,
          tokens: [{ token: 'user_token' }],
          role_associations: subject.role_associations
        };
        stopGrpcMockServer();
        // restart grpcMock with normal user id
        startGrpcMockServer([{ method: 'findByToken', input: '\{.*\:.*\}', output: user }]);
        testRule[0].name = 'new test rule for test entitiy';
        const result = await ruleService.update({
          items: testRule,
          subject
        });
        should.exist(result.error.details);
        result.error.details.should.equal('7 PERMISSION_DENIED: Access not allowed for request with subject:user_id, resource:rule, action:MODIFY, target_scope:orgC; the response was DENY');
      });

      it('should allow to upsert rule with valid subject scope', async () => {
        // change subject to admin user
        subject.id = 'admin_user_id';
        subject.role_associations[0].role = 'admin-r-id';
        subject.token = 'admin_token';
        const user = {
          id: subject.id,
          tokens: [{ token: 'admin_token' }],
          role_associations: subject.role_associations
        };
        stopGrpcMockServer();
        // restart grpcMock with admin user id
        startGrpcMockServer([{ method: 'findByToken', input: '\{.*\:.*\}', output: user }]);

        testRule[0].name = 'upserted test rule for test entitiy';
        const result = await ruleService.upsert({
          items: testRule,
          subject
        });
        should.exist(result.data.items);
        result.data.items[0].name.should.equal('upserted test rule for test entitiy');
      });

      it('should not allow to upsert rule with invalid subject scope', async () => {
        // change subject to normal user
        subject.id = 'user_id';
        subject.role_associations[0].role = 'user-r-id';

        subject.token = 'user_token';
        const user = {
          id: subject.id,
          tokens: [{ token: 'user_token' }],
          role_associations: subject.role_associations
        };
        stopGrpcMockServer();
        // restart grpcMock with normal user id
        startGrpcMockServer([{ method: 'findByToken', input: '\{.*\:.*\}', output: user }]);
        testRule[0].name = 'new test rule for test entitiy';
        const result = await ruleService.upsert({
          items: testRule,
          subject
        });
        should.exist(result.error.details);
        result.error.details.should.equal('7 PERMISSION_DENIED: Access not allowed for request with subject:user_id, resource:rule, action:MODIFY, target_scope:orgC; the response was DENY');
      });

      it('should not allow to delete rule with invalid subject scope', async () => {
        // change subject to admin user
        subject.id = 'user_id';
        subject.role_associations[0].role = 'user-r-id';
        const result = await ruleService.delete({
          ids: testRule[0].id,
          subject
        });
        should.exist(result.error.details);
        result.error.details.should.equal('7 PERMISSION_DENIED: Access not allowed for request with subject:user_id, resource:rule, action:DELETE, target_scope:orgC; the response was DENY');
      });

      it('should allow to delete rule with valid subject scope', async () => {
        // change subject to admin user
        subject.id = 'admin_user_id';
        subject.role_associations[0].role = 'admin-r-id';
        subject.token = 'admin_token';
        const user = {
          id: subject.id,
          tokens: [{ token: 'admin_token' }],
          role_associations: subject.role_associations
        };
        stopGrpcMockServer();
        // restart grpcMock with admin user id
        startGrpcMockServer([{ method: 'findByToken', input: '\{.*\:.*\}', output: user }]);
        const result = await ruleService.delete({
          ids: testRule[0].id,
          subject
        });
        should.exist(result.data);
        result.data.should.be.empty();
      });
    });
  });
});
