import * as _ from 'lodash';
import * as traverse from 'traverse';
import { Logger } from 'winston';

import { Target, Request, Attribute, AccessController } from '.';
import { Resource } from './interfaces';

const getAllValues = (obj: any, pushedValues: any): any => {
  for (let value of (<any>Object).values(obj)) {
    if (_.isArray(value)) {
      getAllValues(value, pushedValues);
    } else if (typeof value == 'string') {
      pushedValues.push(value);
    } else {
      // It is an object
      getAllValues(value, pushedValues);
    }
  }
};

export const checkHierarchicalScope = async (ruleTarget: Target,
  request: Request, urns: Map<string, string>, accessController: AccessController, logger?: Logger): Promise<boolean> => {
  const scopedRoles = new Map<string, Map<string, string[]>>(); // <role, <scopingEntity, scopingInstances[]>>
  let role: string;
  const totalScopingEntities: string[] = [];
  const ruleSubject = ruleTarget.subject || [];
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

  let context = request.context;
  if (_.isEmpty(context)) {
    return false; // no context was provided, evaluation fails
  }

  const ctxResources = context.resources || [];
  const reqTarget = request.target;
  let currentResourceEntity: string;
  // iterating through all targeted resources and retrieve relevant owner instances
  for (let attribute of ruleTarget.resources) {
    if (attribute.id == urns.get('entity')) { // resource type found
      logger.debug('Evaluating resource entity match');
      currentResourceEntity = attribute.value;

      let entitiesMatch = false;
      // iterating request resources to filter all resources of a given type
      for (let reqAttribute of reqTarget.resources) {
        if (reqAttribute.id == attribute.id && reqAttribute.value == currentResourceEntity) {
          entitiesMatch = true; // a resource entity that matches the request and the rule's target
        } else if (reqAttribute.id == attribute.id) {
          // Add Regex matching and set entitiesMatch to true
          let pattern = currentResourceEntity.substring(currentResourceEntity.lastIndexOf(':') + 1);
          // let regexValue = pattern.split('.')[0];
          // get Entity name last element
          let regexValue = pattern.split(/[.]+/).pop();
          const reExp = new RegExp(regexValue);
          if (reqAttribute.value.match(reExp)) {
            entitiesMatch = true;
          }
        }
        else if (reqAttribute.id == urns.get('resourceID') && entitiesMatch) { // resource instance ID of a matching entity
          const instanceID = reqAttribute.value;
          // found resource instance ID, iterating through the context to check if owner entities match the scoping entities
          let ctxResource: Resource = _.find(ctxResources, ['instance.id', instanceID]);
          // ctxResource = ctxResource.instance;
          if (ctxResource) {
            ctxResource = ctxResource.instance;
          } else {
            // look up by ID
            ctxResource = _.find(ctxResources, ['id', instanceID]);
          }
          if (ctxResource) {
            const meta = ctxResource.meta;

            if (_.isEmpty(meta) || _.isEmpty(meta.owner)) {
              logger.debug(`Owner information missing for hierarchical scope matching of entity ${attribute.value}, evaluation fails`);
              return false; // no ownership was passed, evaluation fails
            }

            let ownerEntity: string;
            for (let owner of meta.owner) {
              if (owner.id == urns.get('ownerEntity')) {
                if (_.find(totalScopingEntities, e => e == owner.value)) {
                  ownerEntity = owner.value;
                }
              } else if (owner.id == urns.get('ownerInstance') && !!ownerEntity) {
                for (let [role, entities] of scopedRoles) {
                  if (entities.has(ownerEntity)) {
                    const instances = entities.get(ownerEntity);
                    instances.push(owner.value);
                    entities.set(ownerEntity, instances);
                    scopedRoles.set(role, entities);
                  }
                }

                ownerEntity = null;
              }
            }
          } else {
            logger.debug('Resource of targeted entity was not provided in context');
            return false; // resource of targeted entity was not provided in context
          }
          entitiesMatch = false;
        }
      }
    } else if (attribute.id === urns.get('operation')) {
      logger.debug('Evaluating resource operation match');
      currentResourceEntity = attribute.value;
      for (let reqAttribute of reqTarget.resources) {
        // match Rule resource operation URN and operation name with request resource operation URN and operation name
        if (reqAttribute.id === attribute.id && reqAttribute.value === attribute.value) {
          if (ctxResources.length === 1) {
            let meta;
            if (ctxResources[0]?.instance) {
              meta = ctxResources[0]?.instance?.meta;
            } else if(ctxResources[0]?.meta) {
              meta = ctxResources[0].meta;
            }

            if (_.isEmpty(meta) || _.isEmpty(meta.owner)) {
              logger.debug(`Owner information missing for hierarchical scope matching of operation ${attribute.value}, evaluation fails`);
              return false; // no ownership was passed, evaluation fails
            }
            let ownerEntity: string;
            for (let owner of meta.owner) {
              if (owner.id == urns.get('ownerEntity')) {
                if (_.find(totalScopingEntities, e => e == owner.value)) {
                  ownerEntity = owner.value;
                }
              } else if (owner.id == urns.get('ownerInstance') && !!ownerEntity) {
                for (let [role, entities] of scopedRoles) {
                  if (entities.has(ownerEntity)) {
                    const instances = entities.get(ownerEntity);
                    instances.push(owner.value);
                    entities.set(ownerEntity, instances);
                    scopedRoles.set(role, entities);
                  }
                }
                ownerEntity = null;
              }
            }
          } else {
            logger.debug('Invalid resource passed', { resource: ctxResources });
            return false;
          }
        }
      }
    }
  }

  if (_.isNil(currentResourceEntity) || _.isEmpty(currentResourceEntity)) {
    logger.debug('No Entity or operation name found');
    return false; // no entity found
  }

  // check if context subject_id contains HR scope if not make request 'createHierarchicalScopes'
  if (context && context.subject && context.subject.token &&
    _.isEmpty(context.subject.hierarchical_scopes)) {
    context = await accessController.createHRScope(context);
  }

  const roleAssociations = context.subject.role_associations;
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
        } else if (attribute.id == urns.get('roleScopingInstance') && !!scopingEntity) { // if scoping instance is found within the attributes
          const instances = entities.get(scopingEntity);
          if (!_.isEmpty(_.remove(instances, i => i == attribute.value))) { // if any element was removed
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
            nodes.push(attribute.value);
            nodesByEntity.set(scopingEntity, nodes);
            treeNodes.set(role, nodesByEntity);
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
                  if (_.find(instances, (i) => {
                    if (eligibleOrgScopes.indexOf(i) > -1) {
                      return true;
                    }
                  })) {
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
