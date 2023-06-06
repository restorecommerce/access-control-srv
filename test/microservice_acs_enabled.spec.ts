import * as should from 'should';
import { Worker } from '../src/worker';
import * as testUtils from './utils';
import * as yaml from 'js-yaml';
import * as fs from 'fs';
import { updateConfig } from '@restorecommerce/acs-client';
import { GrpcMockServer, ProtoUtils } from '@alenon/grpc-mock-server';
import * as proto_loader from '@grpc/proto-loader';
import * as grpc from '@grpc/grpc-js';
import { Topic, Events } from '@restorecommerce/kafka-client';
import { createServiceConfig } from '@restorecommerce/service-config';
import { createLogger } from '@restorecommerce/logger';
import { RuleServiceDefinition, RuleServiceClient, Effect } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/rule';
import { PolicyServiceDefinition, PolicyServiceClient } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/policy';
import { PolicySetServiceDefinition, PolicySetServiceClient } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/policy_set';
import { AccessControlServiceDefinition, AccessControlServiceClient } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/access_control';
import { createChannel, createClient } from '@restorecommerce/grpc-client';

let cfg: any;
let logger;
let worker: Worker;
let ruleService: RuleServiceClient, policyService: PolicyServiceClient, policySetService: PolicySetServiceClient;
let accessControlService: AccessControlServiceClient;
let rules, policies, policySets;
let userTopic: Topic;

// Admin of mainOrg -> A -> B -> C
let subject = {
  id: 'admin_user_id',
  scope: 'orgC',
  token: 'admin_token',
  role_associations: [
    {
      role: 'admin-r-id',
      id: '',
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
    subjects: [{
      id: 'urn:oasis:names:tc:xacml:1.0:subject:subject-id',
      value: 'test-r-id'
    }],
    resources: [{
      id: 'urn:restorecommerce:acs:names:model:entity',
      value: 'urn:restorecommerce:acs:model:test.Test'
    }]
  },
  effect: Effect.PERMIT,
  meta: {
    owners: [{
      id: 'urn:restorecommerce:acs:names:ownerIndicatoryEntity',
      value: 'urn:restorecommerce:acs:model:organization.Organization'
    }, {
      id: 'urn:restorecommerce:acs:names:ownerInstance',
      value: 'orgC'
    }]
  }
}];

interface MethodWithOutput {
  method: string;
  output: any;
};

const PROTO_PATH = 'test/protos/io/restorecommerce/user.proto';
const PKG_NAME = 'io.restorecommerce.user';
const SERVICE_NAME = 'UserService';

const pkgDef: grpc.GrpcObject = grpc.loadPackageDefinition(
  proto_loader.loadSync(PROTO_PATH, {
    includeDirs: ['test/protos'],
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true
  })
);

const proto: any = ProtoUtils.getProtoFromPkgDefinition(
  PKG_NAME,
  pkgDef
);

const mockServer = new GrpcMockServer('localhost:50051');

let adminSubject = {
  id: 'admin_user_id',
  scope: 'mainOrg',
  token: 'admin_token',
  role_associations: [
    {
      role: 'admin-r-id',
      id: '',
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
  tokens: [{ token: 'admin_token' }],
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

let userSubject = {
  id: 'user_id',
  scope: 'orgC',
  token: 'user_token',
  role_associations: [
    {
      role: 'user-r-id',
      id: '',
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
  tokens: [{ token: 'user_token' }],
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

// Mock server for ids - findByToken
const startGrpcMockServer = async (methodWithOutput: MethodWithOutput[]) => {
  // create mock implementation based on the method name and output
  const implementations = {
    findByToken: (call: any, callback: any) => {
      if (call.request.token === 'admin_token') {
        // admin user
        callback(null, { payload: adminSubject, status: { code: 200, message: 'success' } });
      } else if (call.request.token === 'user_token') {
        // user
        callback(null, { payload: userSubject, status: { code: 200, message: 'success' } });
      }
    }
  };
  try {
    mockServer.addService(PROTO_PATH, PKG_NAME, SERVICE_NAME, implementations, {
      includeDirs: ['node_modules/@restorecommerce/protos/'],
      keepCase: true,
      longs: String,
      enums: String,
      defaults: true,
      oneofs: true
    });
    await mockServer.start();
    logger.info('Mock IDS Server started on port 50051');
  } catch (err) {
    logger.error('Error starting mock IDS server', err);
  }
};

const setupService = async (): Promise<void> => {
  cfg = createServiceConfig(process.cwd() + '/test');
  logger = createLogger(cfg.get('logger'));

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

const truncate = async (): Promise<void> => {
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
};

// mock to emit back hierarchicalScopesResponse
const hrScopeReqListener = async (msg) => {
  const token = msg.token.split(':')[0];
  if (token === 'admin_token') {
    const hrScopeResponse = {
      subject_id: 'admin_user_id',
      token: msg.token,
      hierarchical_scopes: subject.hierarchical_scopes
    };
    await userTopic.emit('hierarchicalScopesResponse', hrScopeResponse);
  } else if (token === 'user_token') {
    const hrScopeResponse = {
      subject_id: 'user_id',
      token: msg.token,
      hierarchical_scopes: subject.hierarchical_scopes
    };
    await userTopic.emit('hierarchicalScopesResponse', hrScopeResponse);
  }
};

describe('testing microservice', () => {
  describe('testing resource ownership with ACS Enabled', () => {
    before(async () => {
      await setupService();
      await load('./test/fixtures/default_policies.yml');
      // Add a HR scopeReq listener and send back HR scope response
      // to imitate mock from service which is responsible for creating HR scopes
      // const events = new Events(cfg.get('events:kafka'), logger);
      const events = new Events({
        ...cfg.get('events:kafka'),
        groupId: 'restore-access-control-srv-test-runner',
        kafka: {
          ...cfg.get('events:kafka:kafka'),
        }
      }, logger);
      await events.start();
      userTopic = await events.topic(cfg.get('events:kafka:topics:user:topic'));
      await userTopic.on('hierarchicalScopesRequest', hrScopeReqListener);
    });
    after(async () => {
      await userTopic.removeAllListeners('hierarchicalScopesRequest');
      await truncate();
      await worker.stop();
    });
    describe('testing create() operations', () => {
      it('it should insert default rules, policies and policy sets with ACS disabled', async () => {
        const user = {
          payload: {
            id: 'admin_user_id',
            tokens: [{ token: 'admin_token' }],
            role_associations: subject.role_associations
          },
          status: {
            code: 200,
            message: 'success'
          }
        };
        // start mock ids-srv needed for findByToken response and return subject
        await startGrpcMockServer([{ method: 'findByToken', output: user }]);
        await new Promise(r => setTimeout(r, 2000));
        // disable authorization
        cfg.set('authorization:enabled', false);
        cfg.set('authorization:enforce', false);
        updateConfig(cfg);
        const result_policySet = await policySetService.create({
          items: policySets,
          subject
        });
        should.exist(result_policySet);
        should.exist(result_policySet.items);
        result_policySet.items.should.be.length(policySets.length);
        result_policySet.operation_status.code.should.equal(200);
        result_policySet.operation_status.message.should.equal('success');
        const result_policy = await policyService.create({
          items: policies,
          subject
        });
        should.exist(result_policy);
        should.exist(result_policy.items);
        result_policy.items.should.be.length(policies.length);
        result_policy.operation_status.code.should.equal(200);
        result_policy.operation_status.message.should.equal('success');
        const result_rule = await ruleService.create({
          items: rules,
          subject
        });
        should.exist(result_rule);
        should.exist(result_rule.items);
        result_rule.items.should.be.length(rules.length);
        result_rule.operation_status.code.should.equal(200);
        result_rule.operation_status.message.should.equal('success');
      });

      it('should allow to create test rule with ACS enabled with valid scope in subject', async () => {
        // enable authorization
        cfg.set('authorization:enabled', true);
        cfg.set('authorization:enforce', true);
        updateConfig(cfg);
        subject.scope = 'orgC';
        const result = await ruleService.create({
          items: testRule,
          subject
        });
        should.exist(result);
        should.exist(result.items);
        result.items.should.be.length(testRule.length);
        result.operation_status.code.should.equal(200);
        result.operation_status.message.should.equal('success');
      });

      it('should PERMIT to create 2 test rule with ACS enabled with valid scope in subject and delete them', async () => {
        let testRule2 = [{
          name: '1 test rule for test entitiy',
          description: '1 test rule',
          target: {
            subjects: [{
              id: 'urn:oasis:names:tc:xacml:1.0:subject:subject-id',
              value: 'test-r-id'
            }],
            resources: [{
              id: 'urn:restorecommerce:acs:names:model:entity',
              value: 'urn:restorecommerce:acs:model:test.Test'
            }]
          },
          effect: Effect.PERMIT,
          meta: {
            owners: [{
              id: 'urn:restorecommerce:acs:names:ownerIndicatoryEntity',
              value: 'urn:restorecommerce:acs:model:organization.Organization'
            }, {
              id: 'urn:restorecommerce:acs:names:ownerInstance',
              value: 'orgA'
            }]
          }
        }, {
          name: '2 test rule for test entitiy',
          description: '2 test rule',
          target: {
            subjects: [{
              id: 'urn:oasis:names:tc:xacml:1.0:subject:subject-id',
              value: 'test-r-id'
            }],
            resources: [{
              id: 'urn:restorecommerce:acs:names:model:entity',
              value: 'urn:restorecommerce:acs:model:test.Test'
            }]
          },
          effect: Effect.PERMIT,
          meta: {
            owners: [{
              id: 'urn:restorecommerce:acs:names:ownerIndicatoryEntity',
              value: 'urn:restorecommerce:acs:model:organization.Organization'
            }, {
              id: 'urn:restorecommerce:acs:names:ownerInstance',
              value: 'orgB'
            }]
          }
        }];
        subject.scope = 'mainOrg';
        const result = await ruleService.create({
          items: testRule2,
          subject
        });
        should.exist(result);
        should.exist(result.items);
        result.items.should.be.length(testRule2.length);
        result.operation_status.code.should.equal(200);
        result.operation_status.message.should.equal('success');
        const deleteResponse = await ruleService.delete({ ids: [result.items[0].payload.id, result.items[1].payload.id], subject });
        deleteResponse.status[0].id.should.equal(result.items[0].payload.id);
        deleteResponse.status[1].id.should.equal(result.items[1].payload.id);
        deleteResponse.operation_status.code.should.equal(200);
        deleteResponse.operation_status.message.should.equal('success');
      });

      it('should DENY to create 2 test rule with ACS enabled with valid scope in subject and valid owner for 1st instance and invalid owner for 2nd instance', async () => {
        let testRule2 = [{
          name: '1 test rule for test entitiy',
          description: '1 test rule',
          target: {
            subjects: [{
              id: 'urn:oasis:names:tc:xacml:1.0:subject:subject-id',
              value: 'test-r-id'
            }],
            resources: [{
              id: 'urn:restorecommerce:acs:names:model:entity',
              value: 'urn:restorecommerce:acs:model:test.Test'
            }]
          },
          effect: Effect.PERMIT,
          meta: {
            owners: [{
              id: 'urn:restorecommerce:acs:names:ownerIndicatoryEntity',
              value: 'urn:restorecommerce:acs:model:organization.Organization'
            }, {
              id: 'urn:restorecommerce:acs:names:ownerInstance',
              value: 'orgA'
            }]
          }
        }, {
          name: '2 test rule for test entitiy',
          description: '2 test rule',
          target: {
            subjects: [{
              id: 'urn:oasis:names:tc:xacml:1.0:subject:subject-id',
              value: 'test-r-id'
            }],
            resources: [{
              id: 'urn:restorecommerce:acs:names:model:entity',
              value: 'urn:restorecommerce:acs:model:test.Test'
            }]
          },
          effect: Effect.PERMIT,
          meta: {
            owners: [{
              id: 'urn:restorecommerce:acs:names:ownerIndicatoryEntity',
              value: 'urn:restorecommerce:acs:model:organization.Organization'
            }, {
              id: 'urn:restorecommerce:acs:names:ownerInstance',
              value: 'INVALID' // invalid owner org instance
            }]
          }
        }];
        subject.scope = 'orgA';
        const result = await ruleService.create({
          items: testRule2,
          subject
        });
        result.items.should.be.empty();
        result.operation_status.code.should.equal(403);
        result.operation_status.message.should.equal('Access not allowed for request with subject:admin_user_id, resource:rule, action:CREATE, target_scope:orgA; the response was DENY');
      });

      it('should throw an error when trying to create rule with invalid subject scope', async () => {
        // change subject to normal user
        subject.id = 'user_id';
        subject.role_associations[0].role = 'user-r-id';
        subject.token = 'user_token';
        subject.scope = 'orgC';
        const user = {
          payload: {
            id: subject.id,
            tokens: [{ token: 'user_token' }],
            role_associations: subject.role_associations
          },
          status: {
            code: 200,
            message: 'success'
          }
        };
        const result = await ruleService.create({
          items: testRule,
          subject
        });
        should.exist(result);
        result.items.should.be.empty();
        result.operation_status.code.should.equal(403);
        result.operation_status.message.should.equal('Access not allowed for request with subject:user_id, resource:rule, action:CREATE, target_scope:orgC; the response was DENY');
      });

      it('should allow to update rule with valid subject scope', async () => {
        // change subject to admin user
        subject.id = 'admin_user_id';
        subject.role_associations[0].role = 'admin-r-id';
        subject.token = 'admin_token';
        const user = {
          payload: {
            id: subject.id,
            tokens: [{ token: 'admin_token' }],
            role_associations: subject.role_associations
          }
        };
        await new Promise(r => setTimeout(r, 2000));
        testRule[0].name = 'modified test rule for test entitiy';
        const result = await ruleService.update({
          items: testRule,
          subject
        });
        should.exist(result.items);
        result.items[0].payload.name.should.equal('modified test rule for test entitiy');
        result.operation_status.code.should.equal(200);
        result.operation_status.message.should.equal('success');
      });

      it('should not allow to update rule with invalid subject scope', async () => {
        // change subject to normal user
        subject.id = 'user_id';
        subject.role_associations[0].role = 'user-r-id';
        subject.token = 'user_token';
        const user = {
          payload: {
            id: subject.id,
            tokens: [{ token: 'user_token' }],
            role_associations: subject.role_associations
          }
        };
        testRule[0].name = 'new test rule for test entitiy';
        const result = await ruleService.update({
          items: testRule,
          subject
        });
        result.items.should.be.empty();
        result.operation_status.code.should.equal(403);
        result.operation_status.message.should.equal('Access not allowed for request with subject:user_id, resource:rule, action:MODIFY, target_scope:orgC; the response was DENY');
      });

      it('should allow to upsert rule with valid subject scope', async () => {
        // change subject to admin user
        subject.id = 'admin_user_id';
        subject.role_associations[0].role = 'admin-r-id';
        subject.token = 'admin_token';
        const user = {
          payload: {
            id: subject.id,
            tokens: [{ token: 'admin_token' }],
            role_associations: subject.role_associations
          }
        };
        testRule[0].name = 'upserted test rule for test entitiy';
        const result = await ruleService.upsert({
          items: testRule,
          subject
        });
        should.exist(result.items);
        result.items[0].payload.name.should.equal('upserted test rule for test entitiy');
        result.operation_status.code.should.equal(200);
        result.operation_status.message.should.equal('success');
      });

      it('should not allow to upsert rule with invalid subject scope', async () => {
        // change subject to normal user
        subject.id = 'user_id';
        subject.role_associations[0].role = 'user-r-id';

        subject.token = 'user_token';
        const user = {
          payload: {
            id: subject.id,
            tokens: [{ token: 'user_token' }],
            role_associations: subject.role_associations
          }
        };
        testRule[0].name = 'new test rule for test entitiy';
        const result = await ruleService.upsert({
          items: testRule,
          subject
        });
        result.items.should.be.empty();
        result.operation_status.code.should.equal(403);
        result.operation_status.message.should.equal('Access not allowed for request with subject:user_id, resource:rule, action:MODIFY, target_scope:orgC; the response was DENY');
      });

      it('should not allow to delete rule with invalid subject scope', async () => {
        // change subject to admin user
        subject.id = 'user_id';
        subject.role_associations[0].role = 'user-r-id';
        const result = await ruleService.delete({
          ids: [testRule[0].id],
          subject
        });
        result.status.should.be.empty();
        result.operation_status.code.should.equal(403);
        result.operation_status.message.should.equal('Access not allowed for request with subject:user_id, resource:rule, action:DELETE, target_scope:orgC; the response was DENY');
      });

      it('should allow to delete rule with valid subject scope', async () => {
        // change subject to admin user
        subject.id = 'admin_user_id';
        subject.role_associations[0].role = 'admin-r-id';
        subject.token = 'admin_token';
        const user = {
          payload: {
            id: subject.id,
            tokens: [{ token: 'admin_token' }],
            role_associations: subject.role_associations
          }
        };
        const result = await ruleService.delete({
          ids: [testRule[0].id],
          subject
        });
        result.status[0].id.should.equal('test_rule_id');
        result.status[0].code.should.equal(200);
        result.status[0].message.should.equal('success');
        result.operation_status.code.should.equal(200);
        result.operation_status.message.should.equal('success');
      });
    });
  });
});
