import _ from 'lodash-es';
import { Logger } from 'winston';
import { Request } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/access_control.js';
import { Target } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/rule.js';
import { Attribute } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/attribute.js';
import { AccessController } from '.';
import { Resource, ContextWithSubResolved } from './interfaces.js';
import traverse from 'traverse';
import { getAllValues } from './utils.js';

export const verifyACLList = async (ruleTarget: Target,
  request: Request, urns: Map<string, string>, accessController: AccessController, logger?: Logger): Promise<boolean> => {
  const scopedRoles = []; // list of roles in Rule subject
  let role: string;
  const ruleSubject = ruleTarget.subjects || [];
  // retrieving all role scoping entities from the rule's subject
  for (const attribute of ruleSubject) {
    if (attribute.id === urns.get('role')) {
      role = attribute.value;
      scopedRoles.push(role);
    } else if (attribute.id === urns.get('skipACL')) {
      logger.debug('Skipping ACL check as attribute skipACL is set');
      return true;
    }
  }

  let context = (request as any).context as ContextWithSubResolved;
  if (_.isEmpty(context)) {
    logger.debug('No valid context in request');
    (context as any) = {};
  }

  const ctxResources = context.resources || [];
  const reqTarget = request.target;
  // iterating through all targeted resources and retrieve relevant target instances
  const targetScopeEntInstances = new Map<string, string[]>(); // <org.Org, [a, b, c]> OR <user.User, [user1, user2 user3]>
  for (const reqAttribute of reqTarget.resources || []) {
    if (reqAttribute.id == urns.get('resourceID') || (reqAttribute.id === urns.get('operation'))) {
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
        if (meta?.acls?.length > 0) {
          aclList = meta.acls;
        }
      }

      if (_.isEmpty(aclList)) {
        logger.debug('ACL meta data not set and hence no verification is needed');
        return true;
      }

      // verify ACL list
      if (aclList?.length > 0) {
        for (const acl of aclList) {
          if (acl?.id === urns.get('aclIndicatoryEntity')) {
            scopingEntity = acl.value;
            if (!targetScopeEntInstances.get(scopingEntity)) {
              targetScopeEntInstances.set(scopingEntity, []);
            }
            if (!acl.attributes || acl.attributes.length === 0) {
              logger.info('Missing ACL instances');
              return false;
            }
            for (const attribute of acl.attributes) {
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
  if (context?.subject?.token &&
    _.isEmpty(context.subject.hierarchical_scopes)) {
    context = await accessController.createHRScope(context);
  }

  const roleAssociations = context.subject.role_associations;
  if (_.isEmpty(roleAssociations)) {
    logger.info('Role Associations not found in subject for verifying ACL');
    return false; // impossible to evaluate context
  }

  const subjectScopedEntityInstances = new Map<string, string[]>();
  const targetScopingEntities = [...targetScopeEntInstances.keys()]; // keys are the scopingEnt
  for (let i = 0; i < roleAssociations?.length; i += 1) {
    const role: string = roleAssociations[i]?.role;
    const attributes: Attribute[] = roleAssociations[i]?.attributes || [];
    if (scopedRoles.includes(role)) {
      let roleScopingEntity;
      for (const roleAttr of attributes) {
        if (roleAttr?.id === urns.get('roleScopingEntity') && targetScopingEntities.includes(roleAttr?.value)) {
          roleScopingEntity = roleAttr?.value;
          if (!subjectScopedEntityInstances.get(roleAttr?.value)) {
            subjectScopedEntityInstances.set(roleAttr?.value, []);
          }
          if (roleAttr?.attributes?.length > 0) {
            for (const roleInstObj of roleAttr.attributes) {
              if(roleInstObj?.id === urns.get('roleScopingInstance')) {
                subjectScopedEntityInstances?.get(roleScopingEntity)?.push(roleInstObj?.value);
              }
            }
          }
        }
      }
    }
  }

  const actionObj = reqTarget?.actions;
  // verify targetScopeEntInstances with subjectScopedEntityInstances for create action

  if (actionObj && actionObj[0] && actionObj[0].id === urns.get('actionID') &&
    (actionObj[0].value === urns.get('create'))) {
    let validTargetInstances = false;
    if (_.isEmpty(targetScopingEntities)) {
      logger.debug('ACL data was not set in the meta data request, hence no ACL check is done');
      return true;
    }
    for (const scopingEntity of targetScopingEntities) {
      // do not verify the ACL check for subject identifiers
      if ((scopingEntity === urns.get('user')) && (actionObj && actionObj[0] && actionObj[0].id === urns.get('actionID') &&
        (actionObj[0].value === urns.get('create')))) {
        logger.info(`ACL indicatory entity is Subject ${urns.get('user')} and hence no verification is needed`);
        validTargetInstances = true;
        continue;
      }
      const targetInstances = targetScopeEntInstances.get(scopingEntity);
      const subjectInstances = subjectScopedEntityInstances.get(scopingEntity);

      if (!subjectInstances) {
        logger.info('Subject role scoping instances not found for verifying ACL');
        return false; // impossible to evaluate context
      }

      // verify each of targetInstance is under subjectInstances
      // if action is create / modify then only verify the HR scopes (if not direct match should be done)
      const validatedACLInstances: string[] = [];
      if (actionObj && actionObj[0] && actionObj[0].id === urns.get('actionID') &&
        (actionObj[0].value === urns.get('create'))) {
        const hierarchical_scopes = context?.subject?.hierarchical_scopes;
        traverse(hierarchical_scopes).forEach((node: any): any => {
          // match the role with HR node and validate all the targetInstances
          if (scopedRoles.includes(node.role)) {
            const eligibleOrgScopes = [];
            getAllValues(node, eligibleOrgScopes);
            for (const targetInstance of targetInstances) {
              if (eligibleOrgScopes.includes(targetInstance)) {
                logger.debug(`ACL instance ${targetInstance} is valid`);
                validTargetInstances = true;
                validatedACLInstances.push(targetInstance);
                continue;
              } else if (!validatedACLInstances.includes(targetInstance)) {
                logger.info(`ACL instance ${targetInstance} cannot be assigned by subject ${context.subject.id}
                    as subject does not have permissions`);
                validTargetInstances = false;
                break;
              }
            }
          }
        });
        if (!validTargetInstances) {
          return false;
        }
      }
    }
    if (validTargetInstances) {
      return true;
    }
  }

  if (actionObj && actionObj[0] && actionObj[0].id === urns.get('actionID') &&
    (actionObj[0].value === urns.get('read') || actionObj[0].value === urns.get('modify')
      || actionObj[0].value === urns.get('delete'))) {
    let validSubjectInstance = false;
    // if targeScopingEntities is emtpy => no ACL data was sent in meta object / not a target for specific request ID
    if (_.isEmpty(targetScopingEntities)) {
      logger.debug('ACL data was not set in the meta data request, hence no ACL check is done');
      return true;
    }
    for (const scopingEntity of targetScopingEntities) {
      const targetInstances = targetScopeEntInstances.get(scopingEntity);
      const subjectInstances = subjectScopedEntityInstances.get(scopingEntity);

      // if ACL scoping entity is user, then directly verify if the subject id is in the targetInstances
      if (scopingEntity === urns.get('user')) {
        if (targetInstances.includes(context.subject.id)) {
          validSubjectInstance = true;
          break;
        }
      }

      // match atleast one of the subjectOrgInstance is present in targetInstances
      if (subjectInstances?.length > 0) {
        for (const subjectInstance of subjectInstances) {
          // validate atleast one of the subjectInstance is present in the targetInstances list
          // (same role can be assigned with multiple scoping instnaces hence subjectInstances is an array)
          if (targetInstances.includes(subjectInstance)) {
            logger.info(`Valid scope and subject ${context.subject.id} has access`);
            validSubjectInstance = true;
            break;
          }
        }
      }
    }
    if (validSubjectInstance) {
      logger.info(`Subject ${context.subject.id} has valid permissions in ACL list`);
      return true;
    } else {
      logger.info(`Subject ${context.subject.id} does not have permissions in ACL list`);
      return false;
    }
  }

  return false;
};
