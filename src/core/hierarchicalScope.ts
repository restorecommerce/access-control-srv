import * as _ from 'lodash-es';
import traverse from 'traverse';
import { Logger } from 'winston';
import { AccessController } from '.';
import { Request } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/access_control.js';
import { Target } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/rule.js';
import { Attribute } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/attribute.js';
import { Resource, ContextWithSubResolved } from './interfaces.js';
import { getAllValues, updateScopedRoles } from './utils.js';

export const checkHierarchicalScope = async (ruleTarget: Target,
  request: Request, urns: Map<string, string>, accessController: AccessController, logger?: Logger): Promise<boolean> => {
  let scopedRoles = new Map<string, Map<string, string[]>>(); // <role, <scopingEntity, scopingInstances[]>>
  let role: string;
  const totalScopingEntities: string[] = [];
  const ruleSubject = ruleTarget.subjects || [];
  let hierarchicalRoleScopeCheck = 'true';
  // retrieving all role scoping entities from the rule's subject
  for (let attribute of ruleSubject) {
    if (attribute.id == urns.get('role')) {
      role = attribute.value;
      if (!scopedRoles.has(role)) {
        scopedRoles.set(role, new Map<string, string[]>());
      }
    }
    if (attribute.id == urns.get('roleScopingEntity') && !!role) {
      const scopingEntity = attribute.value;

      totalScopingEntities.push(scopingEntity);
      const scopingEntities = scopedRoles.get(role);
      scopingEntities.set(scopingEntity, []);
      scopedRoles.set(role, scopingEntities);
      role = null;
    }
    if (attribute.id === urns.get('hierarchicalRoleScoping')) {
      hierarchicalRoleScopeCheck = attribute.value;
    }
  }

  if (_.isEmpty(totalScopingEntities)) {
    logger.debug('Scoping entity not found in rule subject hence hierarchical scope check not needed');
    return true; // no scoping entities specified in rule, request ignored
  }

  let context = (request as any).context as ContextWithSubResolved;
  if (_.isEmpty(context)) {
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
            scopedRoles = updateScopedRoles(meta, scopedRoles, urns, totalScopingEntities);
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
            scopedRoles = updateScopedRoles(meta, scopedRoles, urns, totalScopingEntities);
          } else {
            logger.debug('Operation name was not provided in context');
            return false; // Operation name was not provided in context
          }
        }
      }
    }
  }

  if (_.isNil(entityOrOperation) || _.isEmpty(entityOrOperation)) {
    logger.debug('No Entity or operation name found');
    return false; // no entity found
  }

  // check if context subject_id contains HR scope if not make request 'createHierarchicalScopes'
  if (context?.subject?.token && _.isEmpty(context.subject.hierarchical_scopes)) {
    context = await accessController.createHRScope(context);
  }

  const roleAssociations = context?.subject?.role_associations;
  if (_.isEmpty(roleAssociations)) {
    logger.debug('Role Associations not found');
    return false; // impossible to evaluate context
  }
  const treeNodes = new Map<string, Map<string, string[]>>(); // <role, <entity, hierarchicalTreeNodes>>

  for (let i = 0; i < roleAssociations.length; i += 1) {
    const role: string = roleAssociations[i].role;
    const attributes: Attribute[] = roleAssociations[i].attributes || [];

    if (scopedRoles.has(role)) {
      const entities = scopedRoles.get(role);
      let scopingEntity: string;
      // let roleSubNodes = []; // sub nodes to be queried in case hierarchical resource is not found
      for (let attribute of attributes) {
        if (attribute.id == urns.get('roleScopingEntity') && entities.has(attribute.value)) {
          scopingEntity = attribute.value;
          if (attribute?.attributes?.length > 0) {
            for (let roleScopeInstObj of attribute.attributes) { // role-attributes-attributes -> roleScopingInstance
              if (roleScopeInstObj.id == urns.get('roleScopingInstance') && !!scopingEntity) {  // if scoping instance is found within the attributes
                const instances = entities.get(scopingEntity);
                if (!_.isEmpty(_.remove(instances, i => i == roleScopeInstObj.value))) { // if any element was removed
                  if (_.isEmpty(instances)) {
                    entities.delete(scopingEntity);
                    if (entities.size == 0) {
                      scopedRoles.delete(role);
                    }
                  }
                } else {
                  if (!treeNodes.has(role)) {
                    treeNodes.set(role, new Map<string, string[]>());
                  }
                  const nodesByEntity = treeNodes.get(role);
                  if (!nodesByEntity.has(scopingEntity)) {
                    nodesByEntity.set(scopingEntity, []);
                  }
                  const nodes = nodesByEntity.get(scopingEntity);
                  nodes.push(roleScopeInstObj.value);
                  nodesByEntity.set(scopingEntity, nodes);
                  treeNodes.set(role, nodesByEntity);
                }
              }
            }
          }
        }
      }
    }
    else {
      if (i == roleAssociations.length - 1 && scopedRoles.size > 0 && treeNodes.size === 0) {
        logger.debug('Subject does not have one of the required roles in its context');
        return false; // user does not have one of the required roles in its context
      }
    }
  }

  let check = scopedRoles.size == 0;
  if (!check && hierarchicalRoleScopeCheck && hierarchicalRoleScopeCheck === 'true') {
    const hierarchicalScopes = context.subject.hierarchical_scopes;
    for (let hierarchicalScope of hierarchicalScopes) {
      let subTreeRole = null;
      let level = -1;
      traverse(hierarchicalScope).forEach(function (node: any): void { // depth-first search
        let subtreeFound = false;
        if (!!node.id) {
          if (level > -1 && this.level >= level) {
            subTreeRole = null;
            level = -1;
          } else {
            if (!subTreeRole) {
              for (let [role, nodes] of treeNodes) {
                for (let [, instances] of nodes) {
                  if (_.includes(instances, node.id)) {
                    subTreeRole = role;
                    subtreeFound = true;
                    break;
                  }
                }
              }
            }
            if (subtreeFound) {
              const entities = scopedRoles.get(subTreeRole);
              let eligibleOrgScopes = [];
              getAllValues(node, eligibleOrgScopes);
              if (entities) {
                for (let [entity, instances] of entities) {
                  for (let instance of instances) {
                    if (eligibleOrgScopes.indexOf(instance) > -1) {
                      instances = instances.filter(e => e != instance);
                    }
                  }
                  if (instances.length === 0) {
                    entities.delete(entity);
                    break;
                  }
                }
              }
              if (entities && entities.size == 0) {
                scopedRoles.delete(subTreeRole);
                if (scopedRoles.size == 0) {
                  check = true;
                  this.stop(); // stopping traversal, no more scoped roles need to be checked
                }
              }
              // inside hierarchical sub
            }
          }
        }
      });
    }
  }

  return check;
};
