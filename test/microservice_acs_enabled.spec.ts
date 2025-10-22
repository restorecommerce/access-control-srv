import {} from 'mocha';
import should from 'should';
import { Worker } from '../src/worker.js';
import * as testUtils from './utils.js';
import yaml from 'js-yaml';
import fs from 'node:fs';
import { updateConfig } from '@restorecommerce/acs-client';
import { GrpcMockServer } from '@alenon/grpc-mock-server';
import proto_loader from '@grpc/proto-loader';
import grpc from '@grpc/grpc-js';
import { Topic, Events } from '@restorecommerce/kafka-client';
import {
  RuleServiceDefinition,
  RuleServiceClient,
  Effect
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/rule.js';
import {
  PolicyServiceDefinition,
  PolicyServiceClient
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/policy.js';
import {
  PolicySetServiceDefinition,
  PolicySetServiceClient
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/policy_set.js';
import {
  createChannel,
  createClient
} from '@restorecommerce/grpc-client';
import { cfg, logger } from './utils.js';

let worker: Worker;
let ruleService: RuleServiceClient;
let policyService: PolicyServiceClient;
let policySetService: PolicySetServiceClient;
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
        value: 'urn:restorecommerce:acs:model:organization.Organization',
        attributes: [{
          id: 'urn:restorecommerce:acs:names:roleScopingInstance',
          value: 'mainOrg'
        }]
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
      value: 'urn:restorecommerce:acs:model:organization.Organization',
      attributes: [{
        id: 'urn:restorecommerce:acs:names:ownerInstance',
        value: 'orgC'
      }]
    }]
  }
}];

interface MethodWithOutput {
  method: string;
  output: any;
};

const PROTO_PATH = 'io/restorecommerce/user.proto';
const PKG_NAME = 'io.restorecommerce.user';
const SERVICE_NAME = 'UserService';

const pkgDef: grpc.GrpcObject = grpc.loadPackageDefinition(
  proto_loader.loadSync(PROTO_PATH, {
    includeDirs: ['node_modules/@restorecommerce/protos/'],
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true
  })
);

const mockServer = new GrpcMockServer('localhost:50151');

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
        value: 'urn:restorecommerce:acs:model:organization.Organization',
        attributes: [{
          id: 'urn:restorecommerce:acs:names:roleScopingInstance',
          value: 'mainOrg'
        }]
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
        value: 'urn:restorecommerce:acs:model:organization.Organization',
        attributes: [{
          id: 'urn:restorecommerce:acs:names:roleScopingInstance',
          value: 'mainOrg'
        }]
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
    logger.info('Mock IDS Server started on port 50151');
  } catch (err) {
    logger.error('Error starting mock IDS server', err);
  }
};

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

const load = async (policiesFile: string): Promise<void> => {
  // load from fixtures
  const yamlPolicies = yaml.load(fs.readFileSync(policiesFile).toString());
  const marshalled = testUtils.marshallYamlPolicies(yamlPolicies);

  rules = marshalled.rules;
  policies = marshalled.policies;
  policySets = marshalled.policySets;

  /*
  const acsCfg = cfg.get('client:acs-srv');
  createClient({
    ...acsCfg,
    logger
  }, AccessControlServiceDefinition, createChannel(acsCfg.address));
  */
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
        should.equal(result_policySet.items?.length, policySets.length);
        should.equal(result_policySet.operation_status?.code, 200);
        should.equal(result_policySet.operation_status?.message, 'success');
        const result_policy = await policyService.create({
          items: policies,
          subject
        });
        should.exist(result_policy);
        should.exist(result_policy.items);
        should.equal(result_policy.items?.length, policies.length);
        should.equal(result_policy.operation_status?.code, 200);
        should.equal(result_policy.operation_status?.message, 'success');
        const result_rule = await ruleService.create({
          items: rules,
          subject
        });
        should.exist(result_rule);
        should.exist(result_rule.items);
        should.equal(result_rule.items?.length, rules.length);
        should.equal(result_rule.operation_status?.code, 200);
        should.equal(result_rule.operation_status?.message, 'success');
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
        should.equal(result.items?.length, testRule.length);
        should.equal(result.operation_status?.code, 200);
        should.equal(result.operation_status?.message, 'success');
      });

      it('should allow to create test rule with ACS enabled without providing scope in subject', async () => {
        // enable authorization
        cfg.set('authorization:enabled', true);
        cfg.set('authorization:enforce', true);
        updateConfig(cfg);
        const result = await ruleService.create({
          items: [{
            ...testRule[0],
            id: 'test_rule_id2',
          }],
          subject
        });
        should.exist(result);
        should.exist(result.items);
        should.equal(result.items?.length, testRule.length);
        should.equal(result.operation_status?.code, 200);
        should.equal(result.operation_status?.message, 'success');
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
              value: 'urn:restorecommerce:acs:model:organization.Organization',
              attributes: [{
                id: 'urn:restorecommerce:acs:names:ownerInstance',
                value: 'orgA'
              }]
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
              value: 'urn:restorecommerce:acs:model:organization.Organization',
              attributes: [{
                id: 'urn:restorecommerce:acs:names:ownerInstance',
                value: 'orgB'
              }]
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
        should.equal(result.items?.length, testRule2.length);
        should.equal(result.operation_status?.code, 200);
        should.equal(result.operation_status?.message, 'success');
        const deleteResponse = await ruleService.delete(
          { 
            ids: result.items?.map(i => i.payload?.id ?? ''),
            subject
          }
        );
        should.equal(deleteResponse.status?.[0].id, result.items?.[0].payload?.id);
        should.equal(deleteResponse.status?.[1].id, result.items?.[1].payload?.id);
        should.equal(deleteResponse.operation_status?.code, 200);
        should.equal(deleteResponse.operation_status?.message, 'success');
      });

      it('should PERMIT to create 2 test rule with ACS enabled with out providing scope in subject and delete them', async () => {
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
              value: 'urn:restorecommerce:acs:model:organization.Organization',
              attributes: [{
                id: 'urn:restorecommerce:acs:names:ownerInstance',
                value: 'orgA'
              }]
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
              value: 'urn:restorecommerce:acs:model:organization.Organization',
              attributes: [{
                id: 'urn:restorecommerce:acs:names:ownerInstance',
                value: 'orgB'
              }]
            }]
          }
        }];
        const result = await ruleService.create({
          items: testRule2,
          subject
        });
        should.exist(result);
        should.exist(result.items);
        should.equal(result.items?.length, testRule2.length);
        should.equal(result.operation_status?.code, 200);
        should.equal(result.operation_status?.message, 'success');
        const deleteResponse = await ruleService.delete(
          { 
            ids: result.items?.map(i => i.payload?.id ?? ''),
            subject
          }
        );
        should.equal(deleteResponse.status?.[0].id, result.items?.[0].payload?.id);
        should.equal(deleteResponse.status?.[1].id, result.items?.[1].payload?.id);
        should.equal(deleteResponse.operation_status?.code, 200);
        should.equal(deleteResponse.operation_status?.message, 'success');
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
              value: 'urn:restorecommerce:acs:model:organization.Organization',
              attributes: [{
                id: 'urn:restorecommerce:acs:names:ownerInstance',
                value: 'orgA'
              }]
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
              value: 'urn:restorecommerce:acs:model:organization.Organization',
              attributes: [{
                id: 'urn:restorecommerce:acs:names:ownerInstance',
                value: 'INVALID' // invalid owner org instance
              }]
            }]
          }
        }];
        subject.scope = 'orgA';
        const result = await ruleService.create({
          items: testRule2,
          subject
        });
        should.not.exist(result.items);
        should.equal(result.operation_status?.code, 403);
        should.equal(
          result.operation_status?.message,
          'Access not allowed for request with subject:admin_user_id, resource:rule, action:CREATE, target_scope:orgA; the response was DENY'
        );
      });

      it('should DENY to create 2 test rule with ACS enabled without providing scope in subject and valid owner for 1st instance and invalid owner for 2nd instance', async () => {
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
              value: 'urn:restorecommerce:acs:model:organization.Organization',
              attributes: [{
                id: 'urn:restorecommerce:acs:names:ownerInstance',
                value: 'orgA'
              }]
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
              value: 'urn:restorecommerce:acs:model:organization.Organization',
              attributes: [{
                id: 'urn:restorecommerce:acs:names:ownerInstance',
                value: 'INVALID' // invalid owner org instance
              }]
            }]
          }
        }];
        const result = await ruleService.create({
          items: testRule2,
          subject
        });
        should.not.exist(result.items);
        should.equal(result.operation_status?.code, 403);
        should.equal(
          result.operation_status?.message,
          'Access not allowed for request with subject:admin_user_id, resource:rule, action:CREATE, target_scope:orgA; the response was DENY'
        );
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
        should.not.exist(result.items);
        should.equal(result.operation_status?.code, 403);
        should.equal(
          result.operation_status?.message,
          'Access not allowed for request with subject:user_id, resource:rule, action:CREATE, target_scope:orgC; the response was DENY'
        );
      });

      it('should throw an error when trying to create rule with out providing scope in subject', async () => {
        // change subject to normal user
        subject.id = 'user_id';
        subject.role_associations[0].role = 'user-r-id';
        subject.token = 'user_token';
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
        should.not.exist(result.items);
        should.equal(result.operation_status?.code, 403);
        should.equal(
          result.operation_status?.message,
          'Access not allowed for request with subject:user_id, resource:rule, action:CREATE, target_scope:orgC; the response was DENY'
        );
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
        should.equal(result.items?.[0]?.payload?.name, 'modified test rule for test entitiy');
        should.equal(result.operation_status?.code, 200);
        should.equal(result.operation_status?.message, 'success');
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
        should.not.exist(result.items);
        should.equal(result.operation_status?.code, 403);
        should.equal(
          result.operation_status?.message,
          'Access not allowed for request with subject:user_id, resource:rule, action:MODIFY, target_scope:orgC; the response was DENY'
        );
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
        should.equal(result.items?.[0]?.payload?.name, 'upserted test rule for test entitiy');
        should.equal(result.operation_status?.code, 200);
        should.equal(result.operation_status?.message, 'success');
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
        should.not.exist(result.items);
        should.equal(result.operation_status?.code, 403);
        should.equal(
          result.operation_status?.message,
          'Access not allowed for request with subject:user_id, resource:rule, action:MODIFY, target_scope:orgC; the response was DENY'
        );
      });

      it('should not allow to delete rule with invalid subject scope', async () => {
        // change subject to admin user
        subject.id = 'user_id';
        subject.role_associations[0].role = 'user-r-id';
        const result = await ruleService.delete({
          ids: [testRule[0].id],
          subject
        });
        should.not.exist(result.status);
        should.equal(result.operation_status?.code, 403);
        should.equal(
          result.operation_status?.message,
          'Access not allowed for request with subject:user_id, resource:rule, action:DELETE, target_scope:orgC; the response was DENY'
        );
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
        should.equal(result.status?.[0].id, 'test_rule_id');
        should.equal(result.status?.[0].code, 200);
        should.equal(result.status?.[0].message, 'success');
        should.equal(result.operation_status?.code, 200);
        should.equal(result.operation_status?.message, 'success');
      });

      // Create with two different scopes assigned for same role
      it('should PERMIT to create test rule with ACS enabled with valid scope in subject with multilple instances assigned to same role', async () => {
        let testRule1 = [{
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
              value: 'urn:restorecommerce:acs:model:organization.Organization',
              attributes: [{
                id: 'urn:restorecommerce:acs:names:ownerInstance',
                value: 'org1'
              }]
            }]
          }
        }];
        // For admin-r-id role Assign two RoleScoped instances (Same Role with 2 different scopes assigned)
        adminSubject.role_associations[0].attributes[0].attributes = [{
          id: 'urn:restorecommerce:acs:names:roleScopingInstance',
          value: 'org1'
        }, {
          id: 'urn:restorecommerce:acs:names:roleScopingInstance',
          value: 'org2'
        }];
        // corresponding HR scopes for two different Orgs
        adminSubject.hierarchical_scopes = [{
          id: 'org1',
          role: 'admin-r-id',
          children: []
        }, {
          id: 'org2',
          role: 'admin-r-id',
          children: []
        }];
        adminSubject.scope = 'org1';
        const result = await ruleService.create({
          items: testRule1,
          subject: adminSubject
        });
        // validate result
        should.equal(result.items?.length, 1);
        should.equal(result.items?.[0]?.payload?.name, '1 test rule for test entitiy');
        should.equal(result.operation_status?.code, 200);
        should.equal(result.operation_status?.message, 'success');

        let testRule2 = [{
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
              value: 'urn:restorecommerce:acs:model:organization.Organization',
              attributes: [{
                id: 'urn:restorecommerce:acs:names:ownerInstance',
                value: 'org2'
              }]
            }]
          }
        }];

        adminSubject.scope = 'org2';
        const result2 = await ruleService.create({
          items: testRule2,
          subject: adminSubject
        });
        // validate result2
        should.equal(result2.items?.length, 1);
        should.equal(result2.items?.[0]?.payload?.name, '2 test rule for test entitiy');
        should.equal(result2.operation_status?.code, 200);
        should.equal(result2.operation_status?.message, 'success');
      });

       // Create with two different scopes assigned for same role
       it('should PERMIT to create test rule with ACS enabled with multiple owners without providing scope in subject with multilple instances assigned to same role', async () => {
        let testRule1 = [{
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
              value: 'urn:restorecommerce:acs:model:organization.Organization',
              attributes: [{
                id: 'urn:restorecommerce:acs:names:ownerInstance',
                value: 'org1'
              }, {
                id: 'urn:restorecommerce:acs:names:ownerInstance',
                value: 'org2'
              }, {
                id: 'urn:restorecommerce:acs:names:ownerInstance',
                value: 'org3'
              }]
            }]
          }
        }];
        // For admin-r-id role Assign two RoleScoped instances (Same Role with 2 different scopes assigned)
        adminSubject.role_associations[0].attributes[0].attributes = [{
          id: 'urn:restorecommerce:acs:names:roleScopingInstance',
          value: 'org1'
        }, {
          id: 'urn:restorecommerce:acs:names:roleScopingInstance',
          value: 'org2'
        }];
        // corresponding HR scopes for two different Orgs
        adminSubject.hierarchical_scopes = [{
          id: 'org1',
          role: 'admin-r-id',
          children: []
        }, {
          id: 'org2',
          role: 'admin-r-id',
          children: []
        }];

        const result = await ruleService.create({
          items: testRule1,
          subject: adminSubject
        });
        // validate result
        should.equal(result.items?.length, 1);
        should.equal(result.items?.[0]?.payload?.name, '1 test rule for test entitiy');
        should.equal(result.operation_status?.code, 200);
        should.equal(result.operation_status?.message, 'success');

        let testRule2 = [{
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
              value: 'urn:restorecommerce:acs:model:organization.Organization',
              attributes: [{
                id: 'urn:restorecommerce:acs:names:ownerInstance',
                value: 'org1'
              }, {
                id: 'urn:restorecommerce:acs:names:ownerInstance',
                value: 'org2'
              }, {
                id: 'urn:restorecommerce:acs:names:ownerInstance',
                value: 'org3'
              }]
            }]
          }
        }];

        const result2 = await ruleService.create({
          items: testRule2,
          subject: adminSubject
        });
        // validate result2
        should.equal(result2.items?.length, 1);
        should.equal(result2.items?.[0]?.payload?.name, '2 test rule for test entitiy');
        should.equal(result2.operation_status?.code, 200);
        should.equal(result2.operation_status?.message, 'success');
      });
    });
  });
});
