import * as mocha from 'mocha';
import * as nock from 'nock';
import * as should from 'should';

import * as core from '../lib/core';
import * as testUtils from './utils';

import * as srvConfig from '@restorecommerce/service-config';
import { Logger } from '@restorecommerce/logger';

const cfg = srvConfig(process.cwd() + '/test');
const acConfig = require('./access_control.json');
const logger = new Logger(cfg.get('logger'));

let ac: core.AccessController;
let request: core.Request;

describe('Testing access control core', () => {
  describe('Testing simple_policies.yml', () => {
    before(() => {
      prepare('./test/fixtures/simple_policies.yml');
    });

    it('should PERMIT based on rule A1', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        resourceType: 'urn:restorecommerce:acs:model:organization.Organization',
        resourceProperty: 'urn:restorecommerce:acs:model:organization.Organization#name',
        resourceID: 'Alice, Inc.',
        actionType: 'urn:restorecommerce:acs:names:action:read'
      });

      await requestAndValidate(ac, request, core.Decision.PERMIT);
    });

    it('should DENY based on rule A2', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Bob',
        resourceType: 'urn:restorecommerce:acs:model:organization.Organization',
        resourceProperty: 'urn:restorecommerce:acs:model:organization.Organization#name',
        resourceID: 'Bob, Inc.',
        actionType: 'urn:restorecommerce:acs:names:action:read'
      });

      await requestAndValidate(ac, request, core.Decision.DENY);
    });

    it('should DENY based on rule A3', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        resourceType: 'urn:restorecommerce:acs:model:organization.Organization',
        resourceProperty: 'urn:restorecommerce:acs:model:organization.Organization#name',
        resourceID: 'Alice, Inc.',
        actionType: 'urn:restorecommerce:acs:names:action:modify'
      });

      await requestAndValidate(ac, request, core.Decision.DENY);
    });

    it('should return INDETERMINATE', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Bob',
        resourceType: 'urn:restorecommerce:acs:model:organization.Organization',
        resourceProperty: 'urn:restorecommerce:acs:model:organization.Organization#name',
        resourceID: 'Bob, Inc.',
        actionType: 'urn:restorecommerce:acs:names:action:modify'
      });

      await requestAndValidate(ac, request, core.Decision.INDETERMINATE);
    });

    it('should return INDETERMINATE', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Steve',
        resourceType: 'urn:restorecommerce:acs:model:organization.Organization',
        resourceProperty: 'urn:restorecommerce:acs:model:organization.Organization#name',
        resourceID: 'Unknown',
        actionType: 'urn:restorecommerce:acs:names:action:modify'
      });

      await requestAndValidate(ac, request, core.Decision.INDETERMINATE);
    });

    it('should return INDETERMINATE', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        resourceType: 'urn:restorecommerce:acs:model:unknown.UnknownResource',
        resourceProperty: 'urn:restorecommerce:acs:model:unknown.UnknownResource#property',
        resourceID: 'Unknown',
        actionType: 'urn:restorecommerce:acs:names:action:read'
      });

      await requestAndValidate(ac, request, core.Decision.INDETERMINATE);
    });

    it('should PERMIT based on combining algorithm from policy B', async () => {
      request = testUtils.buildRequest({
        subjectID: 'John',
        resourceType: 'urn:restorecommerce:acs:model:organization.Organization',
        resourceProperty: 'urn:restorecommerce:acs:model:organization.Organization#name',
        resourceID: 'John GmbH',
        actionType: 'urn:restorecommerce:acs:names:action:read'
      });

      await requestAndValidate(ac, request, core.Decision.PERMIT);
    });

    it('should DENY based on combining algorithm from policy C', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Anna',
        resourceType: 'urn:restorecommerce:acs:model:user.User',
        resourceProperty: 'urn:restorecommerce:acs:model:user.User#password',
        resourceID: 'Anna UG',
        actionType: 'urn:restorecommerce:acs:names:action:read'
      });

      await requestAndValidate(ac, request, core.Decision.DENY);
    });

    it('should DENY based on combining algorithm from policy D', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        resourceType: 'urn:restorecommerce:acs:model:address.Address',
        resourceProperty: 'urn:restorecommerce:acs:model:address.Address#street',
        resourceID: 'Konigstrasse',
        actionType: 'urn:restorecommerce:acs:names:action:read'
      });

      await requestAndValidate(ac, request, core.Decision.DENY);
    });
  });

  describe('Testing policies_with_targets.yml', () => {
    before(() => {
      prepare('./test/fixtures/policies_with_targets.yml');
    });

    it('should PERMIT based on rule A1', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Bob',
        resourceType: 'urn:restorecommerce:acs:model:organization.Organization',
        resourceProperty: 'urn:restorecommerce:acs:model:organization.Organization#sensible_attribute',
        resourceID: 'Bob GmbH',
        actionType: 'urn:restorecommerce:acs:names:action:read'
      });

      await requestAndValidate(ac, request, core.Decision.PERMIT);
    });

    it('should DENY based on rule A2', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Bob',
        resourceType: 'urn:restorecommerce:acs:model:organization.Organization',
        resourceProperty: 'urn:restorecommerce:acs:model:organization.Organization#sensible_attribute',
        resourceID: 'Bob GmbH',
        actionType: 'urn:restorecommerce:acs:names:action:modify'
      });

      await requestAndValidate(ac, request, core.Decision.DENY);
    });

    it('should PERMIT based on policy A\'s combining algorithm', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        resourceType: 'urn:restorecommerce:acs:model:organization.Organization',
        resourceProperty: 'urn:restorecommerce:acs:model:organization.Organization#sensible_attribute',
        resourceID: 'Alice GmbH',
        actionType: 'urn:restorecommerce:acs:names:action:modify'
      });

      await requestAndValidate(ac, request, core.Decision.PERMIT);
    });

    it('should return INDETERMINATE based on policy A\'s target', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        resourceType: 'urn:restorecommerce:acs:model:user.User',
        resourceProperty: 'urn:restorecommerce:acs:model:user.User#password',
        resourceID: 'Alice',
        actionType: 'urn:restorecommerce:acs:names:action:modify'
      });

      await requestAndValidate(ac, request, core.Decision.INDETERMINATE);
    });

    it('should PERMIT based on rule B1', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        resourceType: 'urn:restorecommerce:acs:model:address.Address',
        resourceProperty: 'urn:restorecommerce:acs:model:address.Address#street',
        resourceID: 'Konigstrasse',
        actionType: 'urn:restorecommerce:acs:names:action:modify'
      });

      await requestAndValidate(ac, request, core.Decision.PERMIT);
    });

    it('should PERMIT based on policy C', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Anna',
        resourceType: 'urn:restorecommerce:acs:model:organization.Organization',
        resourceProperty: 'urn:restorecommerce:acs:model:organization.Organization#name',
        resourceID: 'Random',
        actionType: 'urn:restorecommerce:acs:names:action:read'
      });

      await requestAndValidate(ac, request, core.Decision.PERMIT);
    });
  });

  describe('Testing policy_sets_with_targets.yml', () => {
    before(() => {
      prepare('./test/fixtures/policy_sets_with_targets.yml');
    });
    it('should PERMIT based on rule AA3', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        resourceType: 'urn:restorecommerce:acs:model:organization.Organization',
        resourceProperty: 'urn:restorecommerce:acs:model:organization.Organization#name',
        resourceID: 'Random',
        actionType: 'urn:restorecommerce:acs:names:action:read'
      });

      await requestAndValidate(ac, request, core.Decision.PERMIT);
    });

    it('should return INDETERMINATE', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        resourceType: 'urn:restorecommerce:acs:model:user.User',
        resourceProperty: 'urn:restorecommerce:acs:model:user.User#name',
        resourceID: 'Bob',
        actionType: 'urn:restorecommerce:acs:names:action:read'
      });

      await requestAndValidate(ac, request, core.Decision.INDETERMINATE);
    });

    it('should DENY based on rule AA2', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Bob',
        resourceType: 'urn:restorecommerce:acs:model:organization.Organization',
        resourceProperty: 'urn:restorecommerce:acs:model:organization.Organization#name',
        resourceID: 'Random',
        actionType: 'urn:restorecommerce:acs:names:action:modify'
      });

      await requestAndValidate(ac, request, core.Decision.DENY);
    });

    it('should PERMIT based on Rule BA1', async () => {
      request = testUtils.buildRequest({
        subjectID: 'External Bob',
        subjectRole: 'ExternalUser',
        resourceType: 'urn:restorecommerce:acs:model:user.User',
        resourceProperty: 'urn:restorecommerce:acs:model:user.User#name',
        resourceID: 'Bob',
        actionType: 'urn:restorecommerce:acs:names:action:read'
      });

      await requestAndValidate(ac, request, core.Decision.PERMIT);
    });

    it('should DENY based on Rule BA2', async () => {
      request = testUtils.buildRequest({
        subjectID: 'External Bob',
        subjectRole: 'ExternalUser',
        resourceType: 'urn:restorecommerce:acs:model:user.User',
        resourceProperty: 'urn:restorecommerce:acs:model:user.User#name',
        resourceID: 'Bob',
        actionType: 'urn:restorecommerce:acs:names:action:modify'
      });

      await requestAndValidate(ac, request, core.Decision.DENY);
    });
  });

  describe('testing rule with special JS condition', () => {
    before(() => {
      prepare('./test/fixtures/conditions.yml');
    });

    it('should DENY modify request due to special condition', async () => {
      before(() => {
        prepare('./test/fixtures/conditions.yml');
      });

      request = testUtils.buildRequest({
        subjectID: 'Alice',
        resourceType: 'urn:restorecommerce:acs:model:user.User',
        resourceID: 'NotAlice',
        actionType: 'urn:restorecommerce:acs:names:action:modify'
      });

      await requestAndValidate(ac, request, core.Decision.DENY);
    });

    it('should PERMIT modify request due to special condition', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        resourceType: 'urn:restorecommerce:acs:model:user.User',
        resourceID: 'Alice',
        actionType: 'urn:restorecommerce:acs:names:action:modify'
      });

      await requestAndValidate(ac, request, core.Decision.PERMIT);
    });

    it('should DENY due to invalid context in request', async () => {
      request = testUtils.buildRequest({
        subjectID: 'Alice',
        resourceType: 'urn:restorecommerce:acs:model:user.User',
        resourceID: 'Alice',
        actionType: 'urn:restorecommerce:acs:names:action:modify'
      });
      request.context = null;

      await requestAndValidate(ac, request, core.Decision.DENY);
    });
  });
  describe('testing roles with hierarchical scopes', () => {
    before(() => {
      prepare('./test/fixtures/roleScopes.yml');
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

      await requestAndValidate(ac, request, core.Decision.PERMIT);
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

      await requestAndValidate(ac, request, core.Decision.DENY);
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

      await requestAndValidate(ac, request, core.Decision.PERMIT);
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

      await requestAndValidate(ac, request, core.Decision.DENY);
    });
  });
  describe('testing rules with GraphQL queries', () => {
    before(() => {
      prepare('./test/fixtures/context_query.yml');
      ac.createResourceAdapter(cfg.get('adapter'));
    });

    it('should PERMIT based on query result', async () => {
      const scope: nock.Scope = nock('http://example.com').post('/graphql').reply(200, {
        data: {
          getAllAddresses: {
            details: [
              {
                country_id: 'Germany'
              }
            ], error: {
              code: [],
              message: []
            }
          }
        }
      });

      request = testUtils.buildRequest({
        subjectID: 'Alice',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceProperty: 'urn:restorecommerce:acs:model:location.Location#address',
        resourceID: 'Location 1',
        actionType: 'urn:restorecommerce:acs:names:action:modify'
      });
      request.context.resources[0].address = 'Address 1';
      await requestAndValidate(ac, request, core.Decision.PERMIT);
      scope.isDone().should.equal(true);
    });

    it('should DENY based on query result', async () => {
      const scope: nock.Scope = nock('http://example.com').post('/graphql').reply(200, {
        data: {
          getAllAddresses: {
            details: [
              {
                country_id: 'Finland'
              }
            ],
            error: {
              code: [],
              message: []
            }
          }
        }
      });

      request = testUtils.buildRequest({
        subjectID: 'Alice',
        resourceType: 'urn:restorecommerce:acs:model:location.Location',
        resourceProperty: 'urn:restorecommerce:acs:model:location.Location#address',
        resourceID: 'Location 1',
        actionType: 'urn:restorecommerce:acs:names:action:modify'
      });
      request.context.resources[0].address = 'Address 1';
      await requestAndValidate(ac, request, core.Decision.DENY);
      scope.isDone().should.equal(true);
    });
  });
});

// Helper functions
function prepare(filepath: string): void {
  ac = new core.AccessController(logger, acConfig);
  testUtils.populate(ac, filepath);
}


async function requestAndValidate(ac: core.AccessController, request: core.Request, expectedDecision: core.Decision): Promise<void> {
  const response: core.Response = await ac.isAllowed(request);
  should.exist(response);
  should.exist(response.decision);
  const decision: core.Decision = response.decision;
  decision.should.equal(expectedDecision);
}
