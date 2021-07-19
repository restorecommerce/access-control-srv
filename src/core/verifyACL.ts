import * as _ from 'lodash';
import { Logger } from 'winston';

import { Target, Request, Attribute, AccessController } from '.';
import { Resource } from './interfaces';
import * as traverse from 'traverse';
import { getAllValues } from './utils';

export const verifyACLList = async (ruleTarget: Target,
  request: Request, urns: Map<string, string>, accessController: AccessController, logger?: Logger): Promise<boolean> => {
  const scopedRoles = []; // list of roles in Rule subject
  let role: string;
  const ruleSubject = ruleTarget.subject || [];
  // retrieving all role scoping entities from the rule's subject
  for (let attribute of ruleSubject) {
    if (attribute.id == urns.get('role')) {
      role = attribute.value;
      scopedRoles.push(role);
    }
  }

  let context = request.context;
  if (_.isEmpty(context)) {
    return false; // no context was provided, evaluation fails
  }

  const ctxResources = context.resources || [];
  const reqTarget = request.target;
  // iterating through all targeted resources and retrieve relevant target instances
  let targetScopeEntInstances = new Map<string, string[]>(); // <org.Org, [a, b, c]> OR <user.User, [user1, user2 user3]>

  for (let reqAttribute of reqTarget.resources) {
    if (reqAttribute.id == urns.get('resourceID')) {
      const instanceID = reqAttribute.value;
      let ctxResource: Resource = _.find(ctxResources, ['instance.id', instanceID]);
      let aclList, scopingEntity;

      if (ctxResource) {
        ctxResource = ctxResource.instance;
      } else {
        // look up by ID
        ctxResource = _.find(ctxResources, ['id', instanceID]);
      }
      if (ctxResource) {
        const meta = ctxResource.meta;
        if (meta && meta.acl && meta.acl.length > 0) {
          aclList = meta.acl;
        }
      }

      if (_.isEmpty(aclList)) {
        logger.debug('ACL meta data not set and hence no verification is needed');
        return true;
      }

      // verify ACL list
      if (!_.isEmpty(aclList) && _.isArray(aclList)) {
        for (let acl of aclList) {
          let aclObj = acl.attribute;
          if (aclObj.id === urns.get('aclIndicatoryEntity')) {
            scopingEntity = aclObj.value;
            if (!targetScopeEntInstances.get(scopingEntity)) {
              targetScopeEntInstances.set(scopingEntity, []);
            }
            for (let attribute of aclObj.attribute) {
              if (attribute.id === urns.get('aclInstance')) {
                targetScopeEntInstances.get(scopingEntity).push(attribute.value);
              } else {
                logger.info('Missing ACL instance value');
                return false;
              }
            }
          } else {
            logger.info('Missing ACL IndicatoryEntity');
            return false;
          }
        }
      }
    }
  }

  // check if context subject_id contains HR scope if not make request 'createHierarchicalScopes'
  if (context && context.subject && context.subject.token &&
    _.isEmpty(context.subject.hierarchical_scopes)) {
    context = await accessController.createHRScope(context);
  }

  const roleAssociations = context.subject.role_associations;
  if (_.isEmpty(roleAssociations)) {
    logger.info('Role Associations not found for verifying ACL');
    return false; // impossible to evaluate context
  }

  let subjectScopedEntityInstances = new Map<string, string[]>();
  let targetScopingEntities = [...targetScopeEntInstances.keys()]; // keys are the scopingEnt
  for (let i = 0; i < roleAssociations.length; i += 1) {
    const role: string = roleAssociations[i].role;
    const attributes: Attribute[] = roleAssociations[i].attributes || [];
    if (scopedRoles.includes(role)) {
      let scopingEntityMatched = false;
      let roleScopingEntity;
      for (let roleAttr of attributes) {
        if (roleAttr.id === urns.get('roleScopingEntity') && targetScopingEntities.includes(roleAttr.value)) {
          scopingEntityMatched = true;
          roleScopingEntity = roleAttr.value;
          if (!subjectScopedEntityInstances.get(roleAttr.value)) {
            subjectScopedEntityInstances.set(roleAttr.value, []);
          }
        } else if (scopingEntityMatched && roleAttr.id === urns.get('roleScopingInstance')) {
          subjectScopedEntityInstances.get(roleScopingEntity).push(roleAttr.value);
        }
      }
    }
  }

  // verify targetScopeEntInstances with subjectScopedEntityInstances
  for (let scopingEntity of targetScopingEntities) {
    // do not verify the ACL check for subject identifiers
    if (scopingEntity === urns.get('user')) {
      logger.info(`ACL indicatory entity is Subject ${urns.get('user')} and hence no verification is needed`);
      continue;
    }
    let targetInstances = targetScopeEntInstances.get(scopingEntity);
    let subjectInstances = subjectScopedEntityInstances.get(scopingEntity);

    if (!subjectInstances) {
      logger.info('Subject role scoping instances not found for verifying ACL');
      return false; // impossible to evaluate context
    }

    // verify each of targetInstance is under subjectInstances
    // if action is create / modify then only verify the HR scopes (if not direct match should be done)
    const actionObj = reqTarget.action;
    if (actionObj && actionObj[0] && actionObj[0].id === urns.get('actionID') &&
      (actionObj[0].value === urns.get('create') || actionObj[0].value === urns.get('modify'))) {
      const hierarchical_scopes = context.subject.hierarchical_scopes;
      let validTargetInstances = true;
      traverse(hierarchical_scopes).forEach((node: any): any => {
        // match the role with HR node and validate all the targetInstances
        if (scopedRoles.includes(node.role)) {
          let eligibleOrgScopes = [];
          getAllValues(node, eligibleOrgScopes);
          for (let targetInstance of targetInstances) {
            if (eligibleOrgScopes.includes(targetInstance)) {
              logger.debug(`ACL instance ${targetInstance} is valid`);
              continue;
            } else {
              logger.info(`ACL instance ${targetInstance} cannot be assigned by subject ${context.subject.id}
                as subject does not have permissions`);
              validTargetInstances = false;
            }
          }
        }
      });
      if (!validTargetInstances) {
        return false;
      }
    } else {
      for (let targetACLInstance of targetInstances) {
        if (subjectInstances.includes(targetACLInstance)) {
          // exatch instance match found
          continue;
        } else {
          logger.info(`Subject ${context.subject.id} does not have permissions to assign ${targetACLInstance}`);
          return false;
        }
      }
    }
  }

  return true;
};
