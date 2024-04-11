import _ from 'lodash-es';
import traverse from 'traverse';
import { Logger } from 'winston';
import { AccessController } from '.';
import { Request } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/access_control.js';
import { Target } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/rule.js';
import { Attribute } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/attribute.js';
import { Resource, ContextWithSubResolved } from './interfaces.js';

export const checkHierarchicalScope = async (ruleTarget: Target,
  request: Request, urns: Map<string, string>, accessController: AccessController, logger?: Logger): Promise<boolean> => {
  // 1) create a Map of resourceID with Owners for resource IDs which have the rule entity matching
  // 2) In HR scope match validate the Owner indicatory entity with vale from matching users Rule's role for
  //    matching role scoping enitty with instance
  let resourceIdOwnersMap = new Map<string, Attribute[]>();
  if (ruleTarget?.subjects?.length === 0) {
    logger.debug('Rule subject not configured, hence hierarchical scope check not needed');
    return true; // no scoping entities specified in rule, request ignored
  }
  let hierarchicalRoleScopeCheck = 'true'; // default is to check for HR scope for all resources
  let ruleRole: string;
  const roleURN = urns.get('role');
  let ruleRoleScopingEntity: string; // target scoping entity to match from owners and role associations
  ruleTarget?.subjects?.forEach((subjectObject) => {
    if (subjectObject?.id === roleURN) {
      ruleRole = subjectObject?.value;
    } else if (subjectObject?.id === urns.get('hierarchicalRoleScoping')) {
      hierarchicalRoleScopeCheck = subjectObject.value;
    } else if (subjectObject?.id === urns.get('roleScopingEntity')) {
      ruleRoleScopingEntity = subjectObject.value;
    }
  });

  if (!ruleRoleScopingEntity) {
    logger.debug('Scoping entity not found in rule subject hence hierarchical scope check not needed');
    return true; // no scoping entities specified in rule, request ignored
  }

  let context = (request as any).context as ContextWithSubResolved;
  if (_.isEmpty(context)) {
    logger.debug('Empty context, evaluation fails');
    return false; // no context was provided, evaluation fails
  }

  const ctxResources = context.resources || [];
  const reqTarget = request.target;
  let entityOrOperation: string;
  // iterating through all targeted resources and retrieve relevant owners instances
  for (let attribute of ruleTarget.resources || []) {
    if (attribute?.id == urns.get('entity')) { // resource type found
      logger.debug('Evaluating resource entity match');
      entityOrOperation = attribute?.value;

      let entitiesMatch = false;
      // iterating request resources to filter all resources of a given type
      for (let requestAttribute of reqTarget.resources || []) {
        if (requestAttribute?.id == attribute?.id && requestAttribute?.value == entityOrOperation) {
          entitiesMatch = true; // a resource entity that matches the request and the rule's target
        } else if (requestAttribute?.id == attribute?.id) {
          // rule entity, get ruleNS and entityRegexValue for rule
          const value = entityOrOperation;
          let pattern = value?.substring(value?.lastIndexOf(':') + 1);
          let nsEntityArray = pattern?.split('.');
          // firstElement could be either entity or namespace
          let nsOrEntity = nsEntityArray[0];
          let entityRegexValue = nsEntityArray[nsEntityArray.length - 1];
          let reqNS, ruleNS;
          if (nsOrEntity?.toUpperCase() != entityRegexValue?.toUpperCase()) {
            // rule name space is present
            ruleNS = nsOrEntity?.toUpperCase();
          }

          // request entity, get reqNS and requestEntityValue for request
          let reqValue = requestAttribute?.value;
          const reqAttributeNS = reqValue?.substring(0, reqValue?.lastIndexOf(':'));
          const ruleAttributeNS = value?.substring(0, value?.lastIndexOf(':'));
          // verify namespace before entity name
          if (reqAttributeNS != ruleAttributeNS) {
            entitiesMatch = false;
          }
          let reqPattern = reqValue?.substring(reqValue?.lastIndexOf(':') + 1);
          let reqNSEntityArray = reqPattern?.split('.');
          // firstElement could be either entity or namespace
          let reqNSOrEntity = reqNSEntityArray[0];
          let requestEntityValue = reqNSEntityArray[reqNSEntityArray.length - 1];
          if (reqNSOrEntity?.toUpperCase() != requestEntityValue?.toUpperCase()) {
            // request name space is present
            reqNS = reqNSOrEntity?.toUpperCase();
          }

          if ((reqNS && ruleNS && (reqNS === ruleNS)) || (!reqNS && !ruleNS)) {
            const reExp = new RegExp(entityRegexValue);
            if (requestEntityValue?.match(reExp)) {
              entitiesMatch = true;
            }
          }
        }
        else if (requestAttribute?.id == urns?.get('resourceID') && entitiesMatch) { // resource instance ID of a matching entity
          const instanceID = requestAttribute?.value;
          // found resource instance ID, iterating through the context to check if owners entities match the scoping entities
          let ctxResource: Resource = _.find(ctxResources ?? [], ['instance.id', instanceID]);
          if (ctxResource) {
            ctxResource = ctxResource?.instance;
          } else {
            // look up by ID
            ctxResource = _.find(ctxResources ?? [], ['id', instanceID]);
          }
          if (ctxResource) {
            const meta = ctxResource.meta;
            if (_.isEmpty(meta) || _.isEmpty(meta.owners)) {
              logger.debug(`Owners information missing for hierarchical scope matching of entity ${attribute.value}, evaluation fails`);
              return false; // no ownership was passed, evaluation fails
            }
            resourceIdOwnersMap.set(instanceID, meta.owners);
          } else {
            logger.debug('Resource of targeted entity was not provided in context');
            return false; // resource of targeted entity was not provided in context
          }
        }
      }
    } else if (attribute?.id === urns.get('operation')) {
      logger.debug('Evaluating resource operation match');
      entityOrOperation = attribute?.value;
      for (let reqAttribute of reqTarget.resources || []) {
        // match Rule resource operation URN and operation name with request resource operation URN and operation name
        if (reqAttribute?.id === attribute?.id && reqAttribute?.value === attribute?.value) {
          // find context resource based
          let ctxResource: Resource = _.find(ctxResources ?? [], ['id', entityOrOperation]);
          if (ctxResource) {
            const meta = ctxResource.meta;
            if (_.isEmpty(meta) || _.isEmpty(meta.owners)) {
              logger.debug(`Owners information missing for hierarchical scope matching of entity ${attribute.value}, evaluation fails`);
              return false; // no ownership was passed, evaluation fails
            }
            resourceIdOwnersMap.set(entityOrOperation, meta.owners);
          } else {
            logger.debug('Operation name was not provided in context');
            return false; // Operation name was not provided in context
          }
        }
      }
    }
  }

  if (!entityOrOperation) {
    logger.debug('No entity or operation name found');
  }

  const roleAssociations = context?.subject?.role_associations;
  if (_.isEmpty(roleAssociations)) {
    logger.debug('Role Associations not found');
    return false; // impossible to evaluate context
  }

  // get all user role association mapping matching the ruleRole -> (Rule Subject's Role)
  const reducedUserRoleAssocs = roleAssociations.filter((obj) => obj.role === ruleRole);

  // verify for exact match, if not then verify from HR scopes
  let deleteMapEntries = [];
  for (let [resourceId, owners] of resourceIdOwnersMap) {
    const entityScopingInstMatch = owners?.some((ownerObj) => {
      return reducedUserRoleAssocs?.some((roleObj) => {
        // check if Rule's roleScoping Entity matches the Owner's role scoping entity and RoleAssociation RoleScoping entity (ex: Organization / User / Klasse etc)
        // and check if roleScoping Instance matches with owner instance
        const match = roleObj?.attributes?.some((roleAttributeObject) => roleAttributeObject?.id === urns.get('roleScopingEntity')
          && ownerObj?.id === urns.get('ownerEntity') && ownerObj.value === ruleRoleScopingEntity && ownerObj.value === roleAttributeObject?.value
          && roleAttributeObject?.attributes?.some((roleInstObj) =>
            roleInstObj?.id === urns.get('roleScopingInstance') && ownerObj?.attributes?.find((ownerInstObj) => ownerInstObj?.value === roleInstObj?.value)));
        logger.debug('Match result for comparing owner indicatory entity and instance with role scoping entity and instance', { match });
        return match;
      });
    });
    if (entityScopingInstMatch) {
      // its not safe to remove entries while iterating, so add entries to array to delete later
      deleteMapEntries.push(resourceId);
    }
  }
  deleteMapEntries.forEach((entry) => resourceIdOwnersMap.delete(entry));

  if (resourceIdOwnersMap.size === 0) {
    logger.info('Role scoping entities and instances matched');
    return true;
  }

  // verify HR scope match
  if (resourceIdOwnersMap.size > 0 && hierarchicalRoleScopeCheck === 'true') {
    // reset deleteMapEntries
    deleteMapEntries = [];
    // check if context subject_id contains HR scope if not make request 'createHierarchicalScopes'
    if (context?.subject?.token && _.isEmpty(context.subject.hierarchical_scopes)) {
      context = await accessController.createHRScope(context);
    }
    const reducedHRScopes = context?.subject?.hierarchical_scopes?.filter((hrObj) => hrObj?.role === ruleRole);
    for (let [resourceId, owners] of resourceIdOwnersMap) {
      // validate scoping Entity first
      let ownerInstance: string;
      const entityMatch = owners?.some((ownerObj) => {
        return reducedUserRoleAssocs?.some((roleObj) => {
          if (roleObj?.attributes?.some((roleAttributeObject) => roleAttributeObject?.id === urns.get('roleScopingEntity')
            && ownerObj?.id === urns.get('ownerEntity') && ownerObj.value === ruleRoleScopingEntity && ownerObj.value === roleAttributeObject?.value)) {
            ownerObj?.attributes?.forEach((obj) => ownerInstance = obj.value);
            return true;
          }
        });
      });
      // validate the ownerInstance from HR scope tree for matched scoping entity
      if (entityMatch && ownerInstance) {
        traverse(reducedHRScopes).forEach((node: any) => { // depth-first search
          if (node?.id === ownerInstance) {
            deleteMapEntries.push(resourceId);
          }
        });
      }
    }
  }

  deleteMapEntries.forEach((entry) => resourceIdOwnersMap.delete(entry));

  if (resourceIdOwnersMap.size === 0) {
    logger.info('Role scoping entities and instances matched from HR scopes');
    return true;
  }

  if (resourceIdOwnersMap.size > 0) {
    const resourceIdOwners = Array.from(resourceIdOwnersMap).map(([resourceId, owners]) => ({ resourceId, owners }));
    logger.info('Subject not in HR Scope', resourceIdOwners);
    return false;
  }
};
