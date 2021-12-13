import * as _ from 'lodash';
import { ResourcesAPIBase, ServiceBase, FilterOperation } from '@restorecommerce/resource-base-interface';
import { Topic, Events } from '@restorecommerce/kafka-client';
import * as core from './core';
import { createMetadata, checkAccessRequest } from './core/utils';
import { AuthZAction, Operation, Decision, ACSAuthZ, DecisionResponse, PolicySetRQResponse } from '@restorecommerce/acs-client';
import { RedisClient } from 'redis';

export interface IAccessControlResourceService<T> {
  load(): Promise<Map<string, T>>;
  readMetaData(id?: string): Promise<any>;
}

const marshallResource = (resource: any, resourceName: string): any => {
  let marshalled: any = _.pick(resource, ['id', 'name', 'description', 'evaluation_cacheable']);
  switch (resourceName) {
    case 'policy_set':
      marshalled = _.assign(marshalled, _.pick(resource, ['target']));
      if (!_.isEmpty(resource)) {
        marshalled.combiningAlgorithm = resource.combining_algorithm;
      }
      marshalled.combinables = new Map<string, core.Policy>();
      break;
    case 'policy':
      marshalled = _.assign(marshalled, _.pick(resource, ['target', 'effect']));
      marshalled.combiningAlgorithm = resource.combining_algorithm;
      marshalled.combinables = new Map<string, core.Rule>();
      break;
    case 'rule':
      marshalled = _.assign(marshalled, _.pick(resource, ['target', 'effect', 'condition']));
      if (!_.isEmpty(resource) && !_.isEmpty(resource.context_query)
        && !_.isEmpty(resource.context_query.query)) {
        marshalled.contextQuery = resource.context_query;
      }
      break;
    default: throw new Error('Unknown resource ' + resourceName);
  }

  return marshalled;
};

const makeFilter = (ids: string[]): any => {
  return [{
    filter: [{
      field: 'id',
      operation: FilterOperation.in,
      value: ids
    }]
  }];
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
    const filters = ruleIDs ? makeFilter(ruleIDs) : {};
    const result = await super.read({
      request: {
        filters
      }
    }, {});

    const rules = new Map<string, core.Rule>();
    if (result && result.items) {
      _.forEach(result.items, (rule) => {
        if (!_.isEmpty(rule?.payload) && rule.payload && rule.payload.id) {
          rules.set(rule.payload.id, marshallResource(rule.payload, 'rule'));
        }
      });
    }

    return rules;
  }

  async readMetaData(id?: string): Promise<any> {
    let result = await super.read({
      request: {
        filters: [{
          filter: [{
            field: 'id',
            operation: FilterOperation.eq,
            value: id
          }]
        }]
      }
    });
    return result;
  }

  async create(call: any, ctx: any): Promise<any> {
    let subject = call.request.subject;
    // update meta data for owner information
    let items = call.request.items;
    items = await createMetadata(items, AuthZAction.CREATE, subject, this);

    let acsResponse: DecisionResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = items;
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'rule', id: items.map(item => item.id) }], AuthZAction.CREATE,
        Operation.isAllowed);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv', err);
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }

    if (acsResponse.decision != Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    const result = await super.create(call, ctx);
    const policySets = _.cloneDeep(_accessController.policySets);

    if (result && result.items) {
      for (let item of result.items) {
        const rule: core.Rule = marshallResource(item.payload, 'rule');
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

  async read(call: any, ctx: any): Promise<any> {
    const readRequest = call.request;
    let subject = call.request.subject;;
    let acsResponse: PolicySetRQResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = [];
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'rule' }], AuthZAction.READ,
        Operation.whatIsAllowed);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv:', err);
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }
    if (acsResponse.decision != Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    if (acsResponse?.custom_query_args && acsResponse.custom_query_args.length > 0) {
      readRequest.custom_queries = acsResponse.custom_query_args[0].custom_queries;
      readRequest.custom_arguments = acsResponse.custom_query_args[0].custom_arguments;
    }
    const result = await super.read({ request: readRequest });
    return result;
  }

  async update(call: any, ctx: any): Promise<any> {
    let subject = call.request.subject;
    // update meta data for owner information
    let items = call.request.items;
    items = await createMetadata(items, AuthZAction.MODIFY, subject, this);

    let acsResponse: DecisionResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = items;
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'rule', id: items.map(item => item.id) }], AuthZAction.MODIFY,
        Operation.isAllowed);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv', err);
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }
    if (acsResponse.decision != Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    const result = await super.update(call, ctx);
    return result;
  }

  async upsert(call: any, ctx: any): Promise<any> {
    let subject = call.request.subject;
    // update meta data for owner information
    let items = call.request.items;
    items = await createMetadata(items, AuthZAction.MODIFY, subject, this);

    let acsResponse: DecisionResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = items;
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'rule', id: items.map(item => item.id) }], AuthZAction.MODIFY,
        Operation.isAllowed);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv', err);
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }
    if (acsResponse.decision != Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    const result = await super.upsert(call, ctx);
    return result;
  }

  async delete(call: any, ctx: any): Promise<any> {
    let resources = [];
    let subject = call.request.subject;
    let ruleIDs = call.request.ids;
    let action, deleteResponse;
    if (ruleIDs) {
      action = AuthZAction.DELETE;
      if (_.isArray(ruleIDs)) {
        for (let id of ruleIDs) {
          resources.push({ id });
        }
      } else {
        resources = [{ id: ruleIDs }];
      }
      Object.assign(resources, { id: ruleIDs });
      await createMetadata(resources, action, subject, this);
    }
    if (call.request.collection) {
      action = AuthZAction.DROP;
      resources = [{ collection: call.request.collection }];
    }

    let acsResponse: DecisionResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = resources;
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'rule', id: ruleIDs }], action,
        Operation.isAllowed);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv:', err);
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }
    if (acsResponse.decision != Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    deleteResponse = await super.delete(call, ctx);
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
    return deleteResponse;
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

  async create(call: any, ctx: any): Promise<any> {
    let subject = call.request.subject;
    // update meta data for owner information
    let items = call.request.items;
    items = await createMetadata(items, AuthZAction.CREATE, subject, this);

    let acsResponse: DecisionResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = items;
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'policy', id: items.map(item => item.id) }], AuthZAction.CREATE,
        Operation.isAllowed);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv', err);
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }
    if (acsResponse.decision != Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    const result = await super.create(call, ctx);
    const policySets = _.cloneDeep(_accessController.policySets);

    if (result && result.items) {
      for (let item of result.items) {
        for (let [, policySet] of policySets) {
          if (policySet.combinables.has(item.payload?.id)) {
            const policy: core.Policy = marshallResource(item.payload, 'policy');

            if (_.has(item.payload, 'rules') && !_.isEmpty(item.payload.rules)) {
              policy.combinables = await ruleService.getRules(item.payload.rules);

              if (policy.combinables.size != item.payload.rules.length) {
                for (let id of item.payload.rules) {
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
        filters: [{
          filter: [{
            field: 'id',
            operation: FilterOperation.eq,
            value: id
          }]
        }]
      }
    });
    return result;
  }

  async read(call: any, ctx: any): Promise<any> {
    const readRequest = call.request;
    let subject = call.request.subject;
    let acsResponse: PolicySetRQResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = [];
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'policy' }], AuthZAction.READ,
        Operation.whatIsAllowed);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv:', err);
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }
    if (acsResponse.decision != Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    if (acsResponse?.custom_query_args && acsResponse.custom_query_args.length > 0) {
      readRequest.custom_queries = acsResponse.custom_query_args[0].custom_queries;
      readRequest.custom_arguments = acsResponse.custom_query_args[0].custom_arguments;
    }
    const result = await super.read({ request: readRequest });
    return result;
  }

  async update(call: any, ctx: any): Promise<any> {
    let subject = call.request.subject;
    // update meta data for owner information
    let items = call.request.items;
    items = await createMetadata(items, AuthZAction.MODIFY, subject, this);

    let acsResponse: DecisionResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = items;
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'policy', id: items.map(item => item.id) }], AuthZAction.MODIFY,
        Operation.isAllowed);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv', err);
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }
    if (acsResponse.decision != Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    const result = await super.update(call, ctx);
    return result;
  }

  async upsert(call: any, ctx: any): Promise<any> {
    let subject = call.request.subject;
    // update meta data for owner information
    let items = call.request.items;
    items = await createMetadata(items, AuthZAction.MODIFY, subject, this);

    let acsResponse: DecisionResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = items;
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'policy', id: items.map(item => item.id) }], AuthZAction.MODIFY,
        Operation.isAllowed);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv', err);
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }
    if (acsResponse.decision != Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    const result = await super.upsert(call, ctx);
    return result;
  }

  async getPolicies(policyIDs?: string[]): Promise<Map<string, core.Policy>> {
    const filters = policyIDs ? makeFilter(policyIDs) : {};
    const result = await super.read({
      request: {
        filters
      }
    }, {});

    const policies = new Map<string, core.Policy>();
    if (result && result.items) {
      for (let i = 0; i < result.items.length; i += 1) {
        const policy: core.Policy = marshallResource(result.items[i].payload, 'policy');

        if (!_.isEmpty(result.items[i]?.payload?.rules)) {
          policy.combinables = await this.ruleService.getRules(result.items[i].payload.rules);
          if (policy.combinables.size != result.items[i].payload.rules.length) {
            for (let ruleID of result.items[i].payload.rules) {
              const ruleData = await this.ruleService.getRules([ruleID]);
              if (ruleData.size === 0) {
                this.logger.info(`No rules were found for rule identifier ${ruleID}`);
                continue;
              }
              if (!policy.combinables.has(ruleID) && ruleData.size === 1) {
                policy.combinables.set(ruleID, null);
              }
            }
          }
        }
        if (!_.isEmpty(policy) && policy.id) {
          policies.set(policy.id, policy);
        }
      }
    }

    return policies;
  }

  async delete(call: any, ctx: any): Promise<any> {
    let resources = [];
    let subject = call.request.subject;
    let policyIDs = call.request.ids;
    let action, deleteResponse;
    if (policyIDs) {
      action = AuthZAction.DELETE;
      if (_.isArray(policyIDs)) {
        for (let id of policyIDs) {
          resources.push({ id });
        }
      } else {
        resources = [{ id: policyIDs }];
      }
      Object.assign(resources, { id: policyIDs });
      await createMetadata(resources, action, subject, this);
    }
    if (call.request.collection) {
      action = AuthZAction.DROP;
      resources = [{ collection: call.request.collection }];
    }

    let acsResponse: DecisionResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = resources;
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'policy', id: policyIDs }], action,
        Operation.isAllowed);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv:', err);
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }
    if (acsResponse.decision != Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    deleteResponse = await super.delete(call, ctx);

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
    return deleteResponse;
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
        filters: [{
          filter: [{
            field: 'id',
            operation: FilterOperation.eq,
            value: id
          }]
        }]
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
      if (!item?.payload?.policies) {
        this.logger.warn(`No policies were found for policy set ${item.payload.name}`);
        continue;
      }

      const policySet: core.PolicySet = marshallResource(item.payload, 'policy_set');

      _.forEach(item.payload.policies, (policyID) => {
        if (policies.has(policyID)) {
          policySet.combinables.set(policyID, policies.get(policyID));
        } else {
          this.logger.info(`No policies were found for policy identifier ${policyID}`);
        }
      });

      policySets.set(policySet.id, policySet);
    }

    return policySets;
  }

  async create(call: any, ctx: any): Promise<any> {
    let subject = call.request.subject;
    // update meta data for owner information
    let items = call.request.items;
    items = await createMetadata(items, AuthZAction.CREATE, subject, this);

    let acsResponse: DecisionResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = items;
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'policy_set', id: items.map(item => item.id) }], AuthZAction.CREATE,
        Operation.isAllowed);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv', err);
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }
    if (acsResponse.decision != Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    const result = await super.create(call, ctx);
    if (result && result.items) {
      for (let i = 0; i < result.items.length; i += 1) {
        const policySet: core.PolicySet = marshallResource(result.items[i]?.payload, 'policy_set');
        const policyIDs = result.items[i]?.payload?.policies;
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

  async update(call: any, ctx: any): Promise<any> {
    let subject = call.request.subject;
    // update meta data for owner information
    let items = call.request.items;
    items = await createMetadata(items, AuthZAction.MODIFY, subject, this);

    let acsResponse: DecisionResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = items;
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'policy_set', id: items.map(item => item.id) }], AuthZAction.MODIFY,
        Operation.isAllowed);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv', err);
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }
    if (acsResponse.decision != Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    const result = await super.update(call, ctx);

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

  async delete(call: any, ctx: any): Promise<any> {
    let resources = [];
    let subject = call.request.subject;
    let policySetIDs = call.request.ids;
    let action, deleteResponse;
    if (policySetIDs) {
      action = AuthZAction.DELETE;
      if (_.isArray(policySetIDs)) {
        for (let id of policySetIDs) {
          resources.push({ id });
        }
      } else {
        resources = [{ id: policySetIDs }];
      }
      Object.assign(resources, { id: policySetIDs });
      await createMetadata(resources, action, subject, this);
    }
    if (call.request.collection) {
      action = AuthZAction.DROP;
      resources = [{ collection: call.request.collection }];
    }

    let acsResponse: DecisionResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = resources;
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'policy_set', id: policySetIDs }], action,
        Operation.isAllowed);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv:', err);
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }
    if (acsResponse.decision != Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    deleteResponse = await super.delete(call, ctx);

    if (call.request.ids) {
      for (let id of call.request.ids) {
        _accessController.removePolicySet(id);
      }
    } else if (call.request.collection && call.request.collection == 'policy_set') {
      _accessController.clearPolicies();
    }
    return deleteResponse;
  }

  async read(call: any, ctx: any): Promise<any> {
    const readRequest = call.request;
    let subject = call.request.subject;
    let acsResponse: PolicySetRQResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = [];
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'policy_set' }], AuthZAction.READ,
        Operation.whatIsAllowed);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv:', err);
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }
    if (acsResponse.decision != Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    if (acsResponse?.custom_query_args && acsResponse.custom_query_args.length > 0) {
      readRequest.custom_queries = acsResponse.custom_query_args[0].custom_queries;
      readRequest.custom_arguments = acsResponse.custom_query_args[0].custom_arguments;
    }
    const result = await super.read({ request: readRequest });
    return result;
  }

  async upsert(call: any, ctx: any): Promise<any> {
    let subject = call.request.subject;
    // update meta data for owner information
    let items = call.request.items;
    items = await createMetadata(items, AuthZAction.MODIFY, subject, this);

    let acsResponse: DecisionResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = items;
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'policy_set', id: items.map(item => item.id) }], AuthZAction.MODIFY,
        Operation.isAllowed);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv', err);
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }
    if (acsResponse.decision != Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    const result = await super.upsert(call, ctx);
    return result;
  }
}

export class ResourceManager {

  cfg: any;
  logger: any;
  events: any;
  db: any;
  redisClient: any;
  authZ: any;

  constructor(cfg: any, logger: any, events: Events, db: any,
    accessController: core.AccessController, redisClient: RedisClient, authZ: ACSAuthZ) {
    _accessController = accessController;
    this.cfg = cfg;
    this.logger = logger;
    this.events = events;
    this.db = db;
    this.redisClient = redisClient;
    this.authZ = authZ;
  }

  async setup() {
    const kafkaCfg = this.cfg.get('events:kafka');
    const rulesTopic = await this.events.topic(kafkaCfg.topics['rule.resource'].topic);
    const policyTopic = await this.events.topic(kafkaCfg.topics['policy.resource'].topic);
    const policySetTopic = await this.events.topic(kafkaCfg.topics['policy_set.resource'].topic);

    policySetService = new PolicySetService(this.logger, this.db, policySetTopic, this.cfg, this.redisClient, this.authZ);
    policyService = new PolicyService(this.logger, this.db, policyTopic, rulesTopic, this.cfg, this.redisClient, this.authZ);
    ruleService = new RuleService(this.logger, rulesTopic, this.db, this.cfg, this.redisClient, this.authZ);
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
