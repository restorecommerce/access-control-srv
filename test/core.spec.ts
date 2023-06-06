import * as mocha from 'mocha';
import nock from 'nock';
import * as should from 'should';
import * as core from '../src/core';
import * as testUtils from './utils';
import { createServiceConfig } from '@restorecommerce/service-config';
import { createLogger } from '@restorecommerce/logger';
import { Events } from '@restorecommerce/kafka-client';
import { createChannel, createClient } from '@restorecommerce/grpc-client';
import {  UserServiceDefinition, UserServiceClient } from '@restorecommerce/rc-grpc-clients/dist/generated/io/restorecommerce/user';
import { Request, Response, Response_Decision } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/access_control';

const cfg = createServiceConfig(process.cwd() + '/test');
const acConfig = require('./access_control.json');
const logger = createLogger(cfg.get('logger'));

let ac: core.AccessController;
let request: Request;

// Helper functions
const prepare = async (filepath: string): Promise<void> => {
  const kafkaConfig = cfg.get('events:kafka');
  const events = new Events(kafkaConfig, logger); // Kafka
  await events.start();
  const userTopic = await events.topic(kafkaConfig.topics['user'].topic);
  let userService: UserServiceClient;
  const grpcIDSConfig = cfg.get('client:user');
  if (grpcIDSConfig) {
    userService = createClient({
      ...grpcIDSConfig,
      logger
    }, UserServiceDefinition, createChannel(grpcIDSConfig.address));
  }
  ac = new core.AccessController(logger, acConfig, userTopic, cfg, userService);
  testUtils.populate(ac, filepath);
};

const requestAndValidate = async (ac: core.AccessController, request: Request, expectedDecision: Response_Decision, invalidContext?: boolean): Promise<void> => {
  const response: Response = await ac.isAllowed(request);
  should.exist(response);
  should.exist(response.decision);
  const decision: Response_Decision = response.decision;
  decision.should.equal(expectedDecision);
  if (!invalidContext) {
    response.operation_status.code.should.equal(200);
    response.operation_status.message.should.equal('success');
  }
};

describe('Testing access control core', () => {
  describe('Testing simple_policies.yml', () => {
    before(async () => {
      await prepare('./test/fixtures/simple_policies.yml');
    });

    it('should PERMIT based on rule A1', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:organization.Organization',
        resourceProperty: 'urn:restorecommerce:acs:model:organization.Organization#name',
        resourceID: 'Alice, Inc.',
        actionType: 'urn:restorecommerce:acs:names:action:read'
      });

      await requestAndValidate(ac, request, Response_Decision.PERMIT);
    });

    it('should DENY based on rule A2', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Bob',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:organization.Organization',
        resourceProperty: 'urn:restorecommerce:acs:model:organization.Organization#name',
        resourceID: 'Bob, Inc.',
        actionType: 'urn:restorecommerce:acs:names:action:read'
      });

      await requestAndValidate(ac, request, Response_Decision.DENY);
    });

    it('should DENY based on rule A3', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:organization.Organization',
        resourceProperty: 'urn:restorecommerce:acs:model:organization.Organization#name',
        resourceID: 'Alice, Inc.',
        actionType: 'urn:restorecommerce:acs:names:action:modify'
      });

      await requestAndValidate(ac, request, Response_Decision.DENY);
    });

    it('should return INDETERMINATE', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Bob',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:organization.Organization',
        resourceProperty: 'urn:restorecommerce:acs:model:organization.Organization#name',
        resourceID: 'Bob, Inc.',
        actionType: 'urn:restorecommerce:acs:names:action:modify'
      });

      await requestAndValidate(ac, request, Response_Decision.INDETERMINATE);
    });

    it('should return INDETERMINATE', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Steve',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:organization.Organization',
        resourceProperty: 'urn:restorecommerce:acs:model:organization.Organization#name',
        resourceID: 'Unknown',
        actionType: 'urn:restorecommerce:acs:names:action:modify'
      });

      await requestAndValidate(ac, request, Response_Decision.INDETERMINATE);
    });

    it('should return INDETERMINATE', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:unknown.UnknownResource',
        resourceProperty: 'urn:restorecommerce:acs:model:unknown.UnknownResource#property',
        resourceID: 'Unknown',
        actionType: 'urn:restorecommerce:acs:names:action:read'
      });

      await requestAndValidate(ac, request, Response_Decision.INDETERMINATE);
    });

    it('should PERMIT based on combining algorithm from policy B', async () => {
      request = testUtils.buildRequest({
        subjectID: 'John',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:organization.Organization',
        resourceProperty: 'urn:restorecommerce:acs:model:organization.Organization#name',
        resourceID: 'John GmbH',
        actionType: 'urn:restorecommerce:acs:names:action:read'
      });

      await requestAndValidate(ac, request, Response_Decision.PERMIT);
    });

    it('should DENY based on combining algorithm from policy C', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Anna',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:user.User',
        resourceProperty: 'urn:restorecommerce:acs:model:user.User#password',
        resourceID: 'Anna UG',
        actionType: 'urn:restorecommerce:acs:names:action:read'
      });

      await requestAndValidate(ac, request, Response_Decision.DENY);
    });

    it('should DENY based on combining algorithm from policy D', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:address.Address',
        resourceProperty: 'urn:restorecommerce:acs:model:address.Address#street',
        resourceID: 'Konigstrasse',
        actionType: 'urn:restorecommerce:acs:names:action:read'
      });

      await requestAndValidate(ac, request, Response_Decision.DENY);
    });
  });

  describe('Testing policies_with_targets.yml', () => {
    before(async () => {
      await prepare('./test/fixtures/policies_with_targets.yml');
    });

    it('should PERMIT based on rule A1', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Bob',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:organization.Organization',
        resourceProperty: 'urn:restorecommerce:acs:model:organization.Organization#sensible_attribute',
        resourceID: 'Bob GmbH',
        actionType: 'urn:restorecommerce:acs:names:action:read'
      });

      await requestAndValidate(ac, request, Response_Decision.PERMIT);
    });

    it('should DENY based on rule A2', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Bob',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:organization.Organization',
        resourceProperty: 'urn:restorecommerce:acs:model:organization.Organization#sensible_attribute',
        resourceID: 'Bob GmbH',
        actionType: 'urn:restorecommerce:acs:names:action:modify'
      });

      await requestAndValidate(ac, request, Response_Decision.DENY);
    });

    it('should PERMIT based on policy A\'s combining algorithm', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:organization.Organization',
        resourceProperty: 'urn:restorecommerce:acs:model:organization.Organization#sensible_attribute',
        resourceID: 'Alice GmbH',
        actionType: 'urn:restorecommerce:acs:names:action:modify'
      });

      await requestAndValidate(ac, request, Response_Decision.PERMIT);
    });

    it('should return INDETERMINATE based on policy A\'s target', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:user.User',
        resourceProperty: 'urn:restorecommerce:acs:model:user.User#password',
        resourceID: 'Alice',
        actionType: 'urn:restorecommerce:acs:names:action:modify'
      });

      await requestAndValidate(ac, request, Response_Decision.INDETERMINATE);
    });

    it('should PERMIT based on rule B1', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:address.Address',
        resourceProperty: 'urn:restorecommerce:acs:model:address.Address#street',
        resourceID: 'Konigstrasse',
        actionType: 'urn:restorecommerce:acs:names:action:modify'
      });

      await requestAndValidate(ac, request, Response_Decision.PERMIT);
    });

    it('should PERMIT based on policy C', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Anna',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:organization.Organization',
        resourceProperty: 'urn:restorecommerce:acs:model:organization.Organization#name',
        resourceID: 'Random',
        actionType: 'urn:restorecommerce:acs:names:action:read'
      });

      await requestAndValidate(ac, request, Response_Decision.PERMIT);
    });
  });

  describe('Testing policy_sets_with_targets.yml', () => {
    before(async () => {
      await prepare('./test/fixtures/policy_sets_with_targets.yml');
    });
    it('should PERMIT based on rule AA3', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:organization.Organization',
        resourceProperty: 'urn:restorecommerce:acs:model:organization.Organization#name',
        resourceID: 'Random',
        actionType: 'urn:restorecommerce:acs:names:action:read'
      });

      await requestAndValidate(ac, request, Response_Decision.PERMIT);
    });

    it('should return INDETERMINATE', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:user.User',
        resourceProperty: 'urn:restorecommerce:acs:model:user.User#name',
        resourceID: 'Bob',
        actionType: 'urn:restorecommerce:acs:names:action:read'
      });

      await requestAndValidate(ac, request, Response_Decision.INDETERMINATE);
    });

    it('should DENY based on rule AA2', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Bob',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:organization.Organization',
        resourceProperty: 'urn:restorecommerce:acs:model:organization.Organization#name',
        resourceID: 'Random',
        actionType: 'urn:restorecommerce:acs:names:action:modify'
      });

      await requestAndValidate(ac, request, Response_Decision.DENY);
    });

    it('should PERMIT based on Rule BA1', async () => {
      request = testUtils.buildRequest({
        subjectID: 'External Bob',
        subjectRole: 'ExternalUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:user.User',
        resourceProperty: 'urn:restorecommerce:acs:model:user.User#name',
        resourceID: 'Bob',
        actionType: 'urn:restorecommerce:acs:names:action:read'
      });

      await requestAndValidate(ac, request, Response_Decision.PERMIT);
    });

    it('should DENY based on Rule BA2', async () => {
      request = testUtils.buildRequest({
        subjectID: 'External Bob',
        subjectRole: 'ExternalUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:user.User',
        resourceProperty: 'urn:restorecommerce:acs:model:user.User#name',
        resourceID: 'Bob',
        actionType: 'urn:restorecommerce:acs:names:action:modify'
      });

      await requestAndValidate(ac, request, Response_Decision.DENY);
    });
  });

  describe('testing rule with special JS condition', () => {
    before(async () => {
      await prepare('./test/fixtures/conditions.yml');
    });

    it('should DENY modify request due to special condition', async () => {
      before(async () => {
        await prepare('./test/fixtures/conditions.yml');
      });

      request = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:user.User',
        resourceID: 'NotAlice',
        actionType: 'urn:restorecommerce:acs:names:action:modify'
      });

      await requestAndValidate(ac, request, Response_Decision.DENY);
    });

    it('should PERMIT modify request due to special condition', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:user.User',
        resourceID: 'Alice',
        actionType: 'urn:restorecommerce:acs:names:action:modify'
      });

      await requestAndValidate(ac, request, Response_Decision.PERMIT);
    });

    it('should DENY due to invalid context in request', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:user.User',
        resourceID: 'Alice',
        actionType: 'urn:restorecommerce:acs:names:action:modify'
      });
      request.context = null;

      await requestAndValidate(ac, request, Response_Decision.DENY, true);
    });
  });
  describe('testing roles with hierarchical scopes', () => {
    before(async () => {
      await prepare('./test/fixtures/roleScopes.yml');
    });
    it('should DENY if the context is invalid', async () => {
    });
    it('should PERMIT a read by a SimpleUser', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceID: 'Location 1',
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: 'Org1'
      });
      await requestAndValidate(ac, request, Response_Decision.PERMIT);
    });
    it('should PERMIT a read by a SimpleUser for both Location and Organization', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: ['urn:restorecommerce:acs:model:location.Location', 'urn:restorecommerce:acs:model:organization.Organization'],
        resourceID: ['Location 1', 'Organization 1'],
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: ['Org1', 'Org1']
      });
      await requestAndValidate(ac, request, Response_Decision.PERMIT);
    });
    it('should DENY a read by a SimpleUser for isAllowed operation on Location and Organization resource with resource IDs', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: ['urn:restorecommerce:acs:model:location.Location', 'urn:restorecommerce:acs:model:organization.Organization'],
        resourceID: ['Location 1', 'Organization 1'],
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: ['Org1', 'anotherOrg']
      });
      await requestAndValidate(ac, request, Response_Decision.DENY);
    });
    it('should DENY a modify by a SimpleUser', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceID: 'Location 1',
        actionType: 'urn:restorecommerce:acs:names:action:modify',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: 'Org1'
      });

      await requestAndValidate(ac, request, Response_Decision.DENY);
    });
    it('should PERMIT a modify by an Admin', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'Admin',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'SuperOrg1',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceID: 'Location 1',
        actionType: 'urn:restorecommerce:acs:names:action:modify',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: 'Org1'
      });

      await requestAndValidate(ac, request, Response_Decision.PERMIT);
    });
    it('should DENY a modify by an Admin from another Organization', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'Admin',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org2',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceID: 'Location 1',
        actionType: 'urn:restorecommerce:acs:names:action:modify',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: 'Org1'
      });

      await requestAndValidate(ac, request, Response_Decision.DENY);
    });
    it('should PERMIT Execute action on executeTestMutation by an Admin', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'Admin',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'mutation.executeTestMutation',
        resourceID: 'TestMutate 1',
        actionType: 'urn:restorecommerce:acs:names:action:execute',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: 'Org1'
      });
      await requestAndValidate(ac, request, Response_Decision.PERMIT);
    });
    it('should DENY Execute action on executeTestMutation by an Admin from another organization', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org2',
        resourceType: 'mutation.executeTestMutation',
        resourceID: 'TestMutate 1',
        actionType: 'urn:restorecommerce:acs:names:action:execute',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: 'Org1'
      });
      await requestAndValidate(ac, request, Response_Decision.DENY);
    });
    it('should DENY Execute action on executeTestMutation by a SimpleUser', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'mutation.executeTestMutation',
        resourceID: 'TestMutate 1',
        actionType: 'urn:restorecommerce:acs:names:action:execute',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: 'Org1'
      });
      await requestAndValidate(ac, request, Response_Decision.DENY);
    });
  });
  describe('testing rules with HR scopes disabled', () => {
    before(async () => {
      await prepare('./test/fixtures/hierarchicalScopes_disabled.yml');
    });
    it('should PERMIT a read by a SimpleUser for root Org Scope', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceID: 'Location 1',
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: 'Org1'
      });
      await requestAndValidate(ac, request, Response_Decision.PERMIT);
    });
    it('should DENY a read by a SimpleUser if HR scoping match is disabled', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        targetScopingInstance: 'Org2', // Org2 is targetScope and HR scoping is disabled
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceID: 'Location 1',
        actionType: 'urn:restorecommerce:acs:names:action:read',
        ownerIndicatoryEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        ownerInstance: 'Org2'
      });
      await requestAndValidate(ac, request, Response_Decision.DENY);
    });
  });
  describe('testing rules with GraphQL queries', () => {
    before(async () => {
      await prepare('./test/fixtures/context_query.yml');
      ac.createResourceAdapter(cfg.get('adapter'));
    });

    it('should PERMIT based on query result', async () => {
      const scope: nock.Scope = nock('http://example.com').post('/graphql').reply(200, {
        data: {
          getAllAddresses: {
            details: [
              {
                payload: {
                  country_id: 'Germany'
                }
              }
            ], operation_status: {
              code: 200,
              message: 'success'
            }
          }
        }
      });

      request = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceProperty: 'urn:restorecommerce:acs:model:location.Location#address',
        resourceID: 'Location 1',
        actionType: 'urn:restorecommerce:acs:names:action:modify'
      });
      (request.context as any).resources[0].address = 'Address 1';
      await requestAndValidate(ac, request, Response_Decision.PERMIT);
      scope.isDone().should.equal(true);
    });

    it('should DENY based on query result', async () => {
      const scope: nock.Scope = nock('http://example.com').post('/graphql').reply(200, {
        data: {
          getAllAddresses: {
            details: [
              {
                payload: {
                  country_id: 'Finland'
                }
              }
            ],
            operation_status: {
              code: 200,
              message: 'success'
            }
          }
        }
      });

      request = testUtils.buildRequest({
        subjectID: 'Alice',
        subjectRole: 'SimpleUser',
        roleScopingEntity: 'urn:restorecommerce:acs:model:organization.Organization',
        roleScopingInstance: 'Org1',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceProperty: 'urn:restorecommerce:acs:model:location.Location#address',
        resourceID: 'Location 1',
        actionType: 'urn:restorecommerce:acs:names:action:modify'
      });
      (request.context as any).resources[0].address = 'Address 1';
      await requestAndValidate(ac, request, Response_Decision.DENY);
      scope.isDone().should.equal(true);
    });
  });
});