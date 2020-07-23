import * as _ from 'lodash';
import { ResourcesAPIBase, ServiceBase, toStruct } from '@restorecommerce/resource-base-interface';
import { Topic, Events } from '@restorecommerce/kafka-client';

import * as core from './core';
import { getSubjectFromRedis, createMetadata, AccessResponse, checkAccessRequest, ReadPolicyResponse } from './core/utils';
import { AuthZAction, PermissionDenied, Decision, ACSAuthZ } from '@restorecommerce/acs-client';
import { RedisClient } from 'redis';

export interface IAccessControlResourceService<T> {
  load(): Promise<Map<string, T>>;
  readMetaData(id?: string): Promise<any>;
}

const marshallResource = (resource: any, resourceName: string): any => {
  let marshalled: any = _.pick(resource, ['id', 'name', 'description']);
  switch (resourceName) {
    case 'policy_set':
      marshalled = _.assign(marshalled, _.pick(resource, ['target']));
      marshalled.combiningAlgorithm = resource.combining_algorithm;
      marshalled.combinables = new Map<string, core.Policy>();
      break;
    case 'policy':
      marshalled = _.assign(marshalled, _.pick(resource, ['target', 'effect']));
      marshalled.combiningAlgorithm = resource.combining_algorithm;
      marshalled.combinables = new Map<string, core.Rule>();
      break;
    case 'rule':
      marshalled = _.assign(marshalled, _.pick(resource, ['target', 'effect', 'condition']));
      if (!_.isEmpty(resource.context_query)
        && !_.isEmpty(resource.context_query.query)) {
        marshalled.contextQuery = resource.context_query;
      }
      break;
    default: throw new Error('Unknown resource ' + resourceName);
  }

  return marshalled;
};

const makeFilter = (ids: string[]): any => {
  return toStruct({
    id: {
      $in: ids
    }
  });
};

let _accessController: core.AccessController;
let policySetService: PolicySetService,
  policyService: PolicyService,
  ruleService: RuleService;

/**
* Rule resource service.
*/
export class RuleService extends ServiceBase implements IAccessControlResourceService<core.Rule> {
  cfg: any;
  redisClient: RedisClient;
  authZ: ACSAuthZ;
  constructor(logger: any, policyTopic: Topic, db: any, cfg: any,
    redisClient: RedisClient, authZ: ACSAuthZ) {
    super('rule', policyTopic, logger, new ResourcesAPIBase(db, 'rules'), true);
    this.cfg = cfg;
    this.redisClient = redisClient;
    this.authZ = authZ;
  }

  /**
   * Retrieve and unmarsall Rules data.
   */
  async load(): Promise<Map<string, core.Rule>> {
    return this.getRules();
  }

  async getRules(ruleIDs?: string[]): Promise<Map<string, core.Rule>> {
    const filter = ruleIDs ? makeFilter(ruleIDs) : {};
    const result = await super.read({
      request: {
        filter
      }
    }, {});

    const rules = new Map<string, core.Rule>();
    if (result && result.items) {
      _.forEach(result.items, (rule) => {
        rules.set(rule.id, marshallResource(rule, 'rule'));
      });
    }

    return rules;
  }

  async readMetaData(id?: string): Promise<any> {
    let result = await super.read({
      request: {
        filter: toStruct({
          id: {
            $eq: id
          }
        })
      }
    });
    return result;
  }

  async create(call: any, context: any): Promise<any> {
    let subject = await getSubjectFromRedis(call, this);
    // update meta data for owner information
    let items = call.request.items;
    items = await createMetadata(items, AuthZAction.CREATE, subject, this, this.readMetaData());

    let acsResponse: AccessResponse;
    try {
      acsResponse = await checkAccessRequest(subject, items, AuthZAction.CREATE,
        'rule', this);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv', err);
      throw err;
    }
    if (acsResponse.decision != Decision.PERMIT) {
      throw new PermissionDenied(acsResponse.response.status.message, acsResponse.response.status.code);
    }
    const result = await super.create(call, context);
    const policySets = _.cloneDeep(_accessController.policySets);

    if (result && result.items) {
      for (let item of result.items) {
        const rule: core.Rule = marshallResource(item, 'rule');
        for (let [, policySet] of policySets) {
          for (let [, policy] of policySet.combinables) {
            if (!_.isNil(policy) && policy.combinables.has(rule.id)) {
              _accessController.updateRule(policySet.id, policy.id, rule);
            }
          }
        }
      }
    }
    return result;
  }

  async read(call: any, context: any): Promise<any> {
    const readRequest = call.request;
    let subject = await getSubjectFromRedis(call, this);
    let acsResponse: ReadPolicyResponse;
    try {
      acsResponse = await checkAccessRequest(subject, readRequest, AuthZAction.READ,
        'rule', this);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv:', err);
      throw err;
    }
    if (acsResponse.decision != Decision.PERMIT) {
      throw new PermissionDenied(acsResponse.response.status.message, acsResponse.response.status.code);
    }
    const result = await super.read({ request: readRequest });
    return result;
  }

  async update(call: any, context: any): Promise<any> {
    let subject = await getSubjectFromRedis(call, this);
    // update meta data for owner information
    let items = call.request.items;
    items = await createMetadata(items, AuthZAction.MODIFY, subject, this, this.readMetaData());

    let acsResponse: AccessResponse;
    try {
      acsResponse = await checkAccessRequest(subject, items, AuthZAction.MODIFY,
        'rule', this);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv', err);
      throw err;
    }
    if (acsResponse.decision != Decision.PERMIT) {
      throw new PermissionDenied(acsResponse.response.status.message, acsResponse.response.status.code);
    }
    const result = await super.update(call, context);
    return result;
  }

  async upsert(call: any, context: any): Promise<any> {
    let subject = await getSubjectFromRedis(call, this);
    // update meta data for owner information
    let items = call.request.items;
    items = await createMetadata(items, AuthZAction.MODIFY, subject, this, this.readMetaData());

    let acsResponse: AccessResponse;
    try {
      acsResponse = await checkAccessRequest(subject, items, AuthZAction.MODIFY,
        'rule', this);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv', err);
      throw err;
    }
    if (acsResponse.decision != Decision.PERMIT) {
      throw new PermissionDenied(acsResponse.response.status.message, acsResponse.response.status.code);
    }
    const result = await super.upsert(call, context);
    return result;
  }

  async delete(call: any, context: any): Promise<any> {
    let resources = [];
    let subject = await getSubjectFromRedis(call, this);
    let ruleIDs = call.request.ids;
    if (ruleIDs) {
      if (_.isArray(ruleIDs)) {
        for (let id of ruleIDs) {
          resources.push({ id });
        }
      } else {
        resources = [{ id: ruleIDs }];
      }
      Object.assign(resources, { id: ruleIDs });
      await createMetadata(resources, AuthZAction.DELETE, subject, this, this.readMetaData());
    }
    if (call.request.collection) {
      Object.assign(resources, { collection: call.request.collection });
    }

    let acsResponse: AccessResponse;
    try {
      acsResponse = await checkAccessRequest(subject, resources, AuthZAction.DELETE,
        'rule', this);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv:', err);
      throw err;
    }
    if (acsResponse.decision != Decision.PERMIT) {
      throw new PermissionDenied(acsResponse.response.status.message, acsResponse.response.status.code);
    }
    await super.delete(call, context);
    if (call.request.ids) {
      for (let id of call.request.ids) {
        for (let [, policySet] of _accessController.policySets) {
          for (let [, policy] of policySet.combinables) {
            if (policy.combinables.has(id)) {
              _accessController.removeRule(policySet.id, policy.id, id);
            }
          }
        }
      }
    } else if (call.request.collection && call.request.collection === true) {
      for (let [, policySet] of _accessController.policySets) {
        for (let [, policy] of policySet.combinables) {
          policy.combinables = new Map();
          _accessController.updatePolicy(policySet.id, policy);
        }
      }
    }
  }
}

/**
 * Policy resource service.
 */
export class PolicyService extends ServiceBase implements IAccessControlResourceService<core.Policy> {
  ruleService: RuleService;
  cfg: any;
  redisClient: RedisClient;
  authZ: ACSAuthZ;
  constructor(logger: any, db: any, policyTopic: Topic, rulesTopic: Topic, cfg: any,
    redisClient: RedisClient, authZ: ACSAuthZ) {
    super('policy', policyTopic, logger, new ResourcesAPIBase(db, 'policies'), true);
    this.ruleService = new RuleService(this.logger, rulesTopic, db, cfg, redisClient, authZ);
    this.cfg = cfg;
    this.redisClient = redisClient;
    this.authZ = authZ;
  }

  /**
   * Load rules/policies and map them,
   */
  async load(): Promise<Map<string, core.Policy>> {
    return this.getPolicies();
  }

  async create(call: any, context: any): Promise<any> {
    let subject = await getSubjectFromRedis(call, this);
    // update meta data for owner information
    let items = call.request.items;
    items = await createMetadata(items, AuthZAction.CREATE, subject, this, this.readMetaData());

    let acsResponse: AccessResponse;
    try {
      acsResponse = await checkAccessRequest(subject, items, AuthZAction.CREATE,
        'policy', this);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv', err);
      throw err;
    }
    if (acsResponse.decision != Decision.PERMIT) {
      throw new PermissionDenied(acsResponse.response.status.message, acsResponse.response.status.code);
    }
    const result = await super.create(call, context);
    const policySets = _.cloneDeep(_accessController.policySets);

    if (result && result.items) {
      for (let item of result.items) {
        for (let [, policySet] of policySets) {
          if (policySet.combinables.has(item.id)) {
            const policy: core.Policy = marshallResource(item, 'policy');

            if (_.has(item, 'rules') && !_.isEmpty(item.rules)) {
              policy.combinables = await ruleService.getRules(item.rules);

              if (policy.combinables.size != item.rules.length) {
                for (let id of item.rules) {
                  if (!policy.combinables.has(id)) {
                    policy.combinables.set(id, null);
                  }
                }
              }
            }
            _accessController.updatePolicy(policySet.id, policy);
          }
        }
      }
    }

    return result;
  }

  async readMetaData(id?: string): Promise<any> {
    let result = await super.read({
      request: {
        filter: toStruct({
          id: {
            $eq: id
          }
        })
      }
    });
    return result;
  }

  async read(call: any, context: any): Promise<any> {
    const readRequest = call.request;
    let subject = await getSubjectFromRedis(call, this);
    let acsResponse: ReadPolicyResponse;
    try {
      acsResponse = await checkAccessRequest(subject, readRequest, AuthZAction.READ,
        'policy', this);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv:', err);
      throw err;
    }
    if (acsResponse.decision != Decision.PERMIT) {
      throw new PermissionDenied(acsResponse.response.status.message, acsResponse.response.status.code);
    }
    const result = await super.read({ request: readRequest });
    return result;
  }

  async update(call: any, context: any): Promise<any> {
    let subject = await getSubjectFromRedis(call, this);
    // update meta data for owner information
    let items = call.request.items;
    items = await createMetadata(items, AuthZAction.MODIFY, subject, this, this.readMetaData());

    let acsResponse: AccessResponse;
    try {
      acsResponse = await checkAccessRequest(subject, items, AuthZAction.MODIFY,
        'policy', this);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv', err);
      throw err;
    }
    if (acsResponse.decision != Decision.PERMIT) {
      throw new PermissionDenied(acsResponse.response.status.message, acsResponse.response.status.code);
    }
    const result = await super.update(call, context);
    return result;
  }

  async upsert(call: any, context: any): Promise<any> {
    let subject = await getSubjectFromRedis(call, this);
    // update meta data for owner information
    let items = call.request.items;
    items = await createMetadata(items, AuthZAction.MODIFY, subject, this, this.readMetaData());

    let acsResponse: AccessResponse;
    try {
      acsResponse = await checkAccessRequest(subject, items, AuthZAction.MODIFY,
        'policy', this);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv', err);
      throw err;
    }
    if (acsResponse.decision != Decision.PERMIT) {
      throw new PermissionDenied(acsResponse.response.status.message, acsResponse.response.status.code);
    }
    const result = await super.upsert(call, context);
    return result;
  }

  async getPolicies(policyIDs?: string[]): Promise<Map<string, core.Policy>> {
    const filter = policyIDs ? makeFilter(policyIDs) : {};
    const result = await super.read({
      request: {
        filter
      }
    }, {});

    const policies = new Map<string, core.Policy>();
    if (result && result.items) {
      for (let i = 0; i < result.items.length; i += 1) {
        const policy: core.Policy = marshallResource(result.items[i], 'policy');

        if (!_.isEmpty(result.items[i].rules)) {
          policy.combinables = await this.ruleService.getRules(result.items[i].rules);
          if (policy.combinables.size != result.items[i].rules.length) {
            for (let rule of result.items[i].rules) {
              if (!policy.combinables.has(rule)) {
                policy.combinables.set(rule, null);
              }
            }
          }
        }

        policies.set(policy.id, policy);
      }
    }

    return policies;
  }

  async delete(call: any, context: any): Promise<any> {
    let resources = [];
    let subject = await getSubjectFromRedis(call, this);
    let policyIDs = call.request.ids;
    if (policyIDs) {
      if (_.isArray(policyIDs)) {
        for (let id of policyIDs) {
          resources.push({ id });
        }
      } else {
        resources = [{ id: policyIDs }];
      }
      Object.assign(resources, { id: policyIDs });
      await createMetadata(resources, AuthZAction.DELETE, subject, this, this.readMetaData());
    }
    if (call.request.collection) {
      Object.assign(resources, { collection: call.request.collection });
    }

    let acsResponse: AccessResponse;
    try {
      acsResponse = await checkAccessRequest(subject, resources, AuthZAction.DELETE,
        'policy', this);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv:', err);
      throw err;
    }
    if (acsResponse.decision != Decision.PERMIT) {
      throw new PermissionDenied(acsResponse.response.status.message, acsResponse.response.status.code);
    }
    await super.delete(call, context);

    if (call.request.ids) {
      for (let id of call.request.ids) {
        for (let [, policySet] of _accessController.policySets) {
          if (policySet.combinables.has(id)) {
            _accessController.removePolicy(policySet.id, id);
          }
        }
      }
    } else if (call.request.collection && call.request.collection === true) {
      for (let [, policySet] of _accessController.policySets) {
        policySet.combinables = new Map();
        _accessController.updatePolicySet(policySet);
      }
    }
  }
}

export class PolicySetService extends ServiceBase implements IAccessControlResourceService<core.PolicySet> {
  cfg: any;
  redisClient: RedisClient;
  authZ: ACSAuthZ;
  constructor(logger: any, db: any, policySetTopic: Topic, cfg: any,
    redisClient: RedisClient, authZ: ACSAuthZ) {
    super('policy_set', policySetTopic, logger, new ResourcesAPIBase(db, 'policy_sets'), true);
    this.cfg = cfg;
    this.redisClient = redisClient;
    this.authZ = authZ;
  }

  async readMetaData(id?: string): Promise<any> {
    let result = await super.read({
      request: {
        filter: toStruct({
          id: {
            $eq: id
          }
        })
      }
    });
    return result;
  }

  /**
   * Load policy sets and map them to policies.
   */
  async load(): Promise<Map<string, core.PolicySet>> {
    const data = await super.read({
      request: {}
    }, {});

    if (!data || !data.items || data.items.length == 0) {
      this.logger.warn('No policy sets retrieved from database');
      return;
    }

    const items = data.items;
    const policies = await policyService.load();
    const policySets = new Map<string, core.PolicySet>();

    for (let item of items) {
      if (!item.policies) {
        this.logger.warn(`No policies were found for policy set ${item.name}`);
        continue;
      }

      const policySet: core.PolicySet = marshallResource(item, 'policy_set');

      _.forEach(item.policies, (policyID) => {
        if (policies.has(policyID)) {
          policySet.combinables.set(policyID, policies.get(policyID));
        }
      });

      policySets.set(policySet.id, policySet);
    }

    return policySets;
  }

  async create(call: any, context: any): Promise<any> {
    let subject = await getSubjectFromRedis(call, this);
    // update meta data for owner information
    let items = call.request.items;
    items = await createMetadata(items, AuthZAction.CREATE, subject, this, this.readMetaData());

    let acsResponse: AccessResponse;
    try {
      acsResponse = await checkAccessRequest(subject, items, AuthZAction.CREATE,
        'policy_set', this);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv', err);
      throw err;
    }
    if (acsResponse.decision != Decision.PERMIT) {
      throw new PermissionDenied(acsResponse.response.status.message, acsResponse.response.status.code);
    }
    const result = await super.create(call, context);

    if (result && result.items) {
      for (let i = 0; i < result.items.length; i += 1) {
        const policySet: core.PolicySet = marshallResource(result.items[i], 'policy_set');
        const policyIDs = result.items[i].policies;

        if (!_.isEmpty(policyIDs)) {
          policySet.combinables = await policyService.getPolicies(policyIDs);
          if (policySet.combinables.size != policyIDs.length) {
            for (let id of policyIDs) {
              if (!policySet.combinables.has(id)) {
                policySet.combinables.set(id, null);
              }
            }
          }
        }
        _accessController.updatePolicySet(policySet);
      }
    }

    return result;
  }

  async update(call: any, context: any): Promise<any> {
    let subject = await getSubjectFromRedis(call, this);
    // update meta data for owner information
    let items = call.request.items;
    items = await createMetadata(items, AuthZAction.MODIFY, subject, this, this.readMetaData());

    let acsResponse: AccessResponse;
    try {
      acsResponse = await checkAccessRequest(subject, items, AuthZAction.MODIFY,
        'policy_set', this);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv', err);
      throw err;
    }
    if (acsResponse.decision != Decision.PERMIT) {
      throw new PermissionDenied(acsResponse.response.status.message, acsResponse.response.status.code);
    }
    const result = await super.update(call, context);

    // update in memory policies if no exception was thrown
    for (let item of call.request.items) {
      let policySet = _accessController.policySets.get(item.id);
      let policies = policySet.combinables;

      if (_.has(item, 'policies')) {
        for (let [policyID, policy] of policies) {
          if (_.indexOf(item.policies, policyID) == -1) {
            policies.delete(policyID);
          }
        }

        let missingIDs: string[] = [];
        for (let policyID of item.policies) {
          if (!policySet.combinables.has(policyID)) {
            missingIDs.push(policyID);
          }
        }

        if (!_.isEmpty(missingIDs.length)) {
          const newPolicies = await policyService.getPolicies(missingIDs);
          if (newPolicies.size != missingIDs.length) {  // checking for non-existing policies in DB
            for (let id of missingIDs) {
              if (!newPolicies.has(id)) {
                newPolicies.set(id, null);
              }
            }
          }
          policies = new Map([...policies, ...newPolicies]);
        }
      }

      policySet = _.merge(policySet, marshallResource(item, 'policy_set'));
      policySet.combinables = policies;
      _accessController.policySets.set(policySet.id, policySet);
    }

    return result;
  }

  async delete(call: any, context: any): Promise<any> {
    let resources = [];
    let subject = await getSubjectFromRedis(call, this);
    let policySetIDs = call.request.ids;
    if (policySetIDs) {
      if (_.isArray(policySetIDs)) {
        for (let id of policySetIDs) {
          resources.push({ id });
        }
      } else {
        resources = [{ id: policySetIDs }];
      }
      Object.assign(resources, { id: policySetIDs });
      await createMetadata(resources, AuthZAction.DELETE, subject, this, this.readMetaData());
    }
    if (call.request.collection) {
      Object.assign(resources, { collection: call.request.collection });
    }

    let acsResponse: AccessResponse;
    try {
      acsResponse = await checkAccessRequest(subject, resources, AuthZAction.DELETE,
        'policy_set', this);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv:', err);
      throw err;
    }
    if (acsResponse.decision != Decision.PERMIT) {
      throw new PermissionDenied(acsResponse.response.status.message, acsResponse.response.status.code);
    }
    await super.delete(call, context);

    if (call.request.ids) {
      for (let id of call.request.ids) {
        _accessController.removePolicySet(id);
      }
    } else if (call.request.collection && call.request.collection == 'policy_set') {
      _accessController.clearPolicies();
    }
  }

  async read(call: any, context: any): Promise<any> {
    const readRequest = call.request;
    let subject = await getSubjectFromRedis(call, this);
    let acsResponse: ReadPolicyResponse;
    try {
      acsResponse = await checkAccessRequest(subject, readRequest, AuthZAction.READ,
        'policy', this);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv:', err);
      throw err;
    }
    if (acsResponse.decision != Decision.PERMIT) {
      throw new PermissionDenied(acsResponse.response.status.message, acsResponse.response.status.code);
    }
    const result = await super.read({ request: readRequest });
    return result;
  }

  async upsert(call: any, context: any): Promise<any> {
    let subject = await getSubjectFromRedis(call, this);
    // update meta data for owner information
    let items = call.request.items;
    items = await createMetadata(items, AuthZAction.MODIFY, subject, this, this.readMetaData());

    let acsResponse: AccessResponse;
    try {
      acsResponse = await checkAccessRequest(subject, items, AuthZAction.MODIFY,
        'policy', this);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv', err);
      throw err;
    }
    if (acsResponse.decision != Decision.PERMIT) {
      throw new PermissionDenied(acsResponse.response.status.message, acsResponse.response.status.code);
    }
    const result = await super.upsert(call, context);
    return result;
  }
}

export class ResourceManager {
  constructor(cfg: any, logger: any, events: Events, db: any,
    accessController: core.AccessController, redisClient: RedisClient, authZ: ACSAuthZ) {

    const kafkaCfg = cfg.get('events:kafka');
    const rulesTopic = events.topic(kafkaCfg.topics['rule.resource'].topic);
    const policyTopic = events.topic(kafkaCfg.topics['policy.resource'].topic);
    const policySetTopic = events.topic(kafkaCfg.topics['policy_set.resource'].topic);

    policySetService = new PolicySetService(logger, db, policySetTopic, cfg, redisClient, authZ);
    policyService = new PolicyService(logger, db, policyTopic, rulesTopic, cfg, redisClient, authZ);
    ruleService = new RuleService(logger, rulesTopic, db, cfg, redisClient, authZ);

    _accessController = accessController;
  }

  getResourceService(resource: string): IAccessControlResourceService<any> {
    switch (resource) {
      case 'policy_set':
        return policySetService;
      case 'policy':
        return policyService;
      case 'rule':
        return ruleService;
      default: throw new Error(`Unknown resource ${resource}`);
    }
  }
}
