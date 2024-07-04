import _ from 'lodash-es';
import { ResourcesAPIBase, ServiceBase, FilterOperation } from '@restorecommerce/resource-base-interface';
import { Topic, Events } from '@restorecommerce/kafka-client';
import { AccessController } from './core/accessController.js';
import { createMetadata, checkAccessRequest } from './core/utils.js';
import { AuthZAction, Operation, ACSAuthZ, DecisionResponse, PolicySetRQResponse } from '@restorecommerce/acs-client';
import { RedisClientType } from 'redis';
import { Logger } from 'winston';
import {
  Response_Decision
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/access_control.js';
import {
  PolicySetServiceImplementation,
  PolicySetList, PolicySetListResponse, PolicySet
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/policy_set.js';
import {
  PolicyServiceImplementation,
  PolicyList, PolicyListResponse, Policy
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/policy.js';
import {
  RuleServiceImplementation,
  RuleList, RuleListResponse, Rule
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/rule.js';
import { ReadRequest, Filter_Operation, DeepPartial, DeleteRequest, DeleteResponse } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/resource_base.js';
import { PolicyWithCombinables, PolicySetWithCombinables } from './core/interfaces.js';


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
        marshalled.combining_algorithm = resource.combining_algorithm;
      }
      marshalled.combinables = new Map<string, Policy>();
      break;
    case 'policy':
      marshalled = _.assign(marshalled, _.pick(resource, ['target', 'effect']));
      marshalled.combining_algorithm = resource.combining_algorithm;
      marshalled.combinables = new Map<string, Rule>();
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
    filters: [{
      field: 'id',
      operation: FilterOperation.in,
      value: ids
    }]
  }];
};

let _accessController: AccessController;
let policySetService: PolicySetService,
  policyService: PolicyService,
  ruleService: RuleService;

/**
* Rule resource service.
*/
export class RuleService extends ServiceBase<RuleListResponse, RuleList> implements IAccessControlResourceService<Rule>, RuleServiceImplementation {
  cfg: any;
  redisClient: RedisClientType<any, any>;
  authZ: ACSAuthZ;
  constructor(logger: any, policyTopic: Topic, db: any, cfg: any,
    redisClient: RedisClientType<any, any>, authZ: ACSAuthZ) {
    let resourceFieldConfig;
    if (cfg.get('fieldHandlers')) {
      resourceFieldConfig = cfg.get('fieldHandlers');
      resourceFieldConfig['bufferFields'] = resourceFieldConfig?.bufferFields?.users;
      if (cfg.get('fieldHandlers:timeStampFields')) {
        resourceFieldConfig['timeStampFields'] = [];
        for (let timeStampFiledConfig of cfg.get('fieldHandlers:timeStampFields')) {
          if (timeStampFiledConfig.entities.includes('rules')) {
            resourceFieldConfig['timeStampFields'].push(...timeStampFiledConfig.fields);
          }
        }
      }
    }
    super('rule', policyTopic, logger, new ResourcesAPIBase(db, 'rules', resourceFieldConfig), true);
    this.cfg = cfg;
    this.redisClient = redisClient;
    this.authZ = authZ;
  }

  /**
   * Retrieve and unmarsall Rules data.
   */
  async load(): Promise<Map<string, Rule>> {
    return this.getRules();
  }

  // async reloadRules(result: DeepPartial<RuleListResponse>): Promise<void> {
  //   const policySets = _.cloneDeep(_accessController.policySets);
  //   if (result?.items?.length > 0) {
  //     for (let item of result.items) {
  //       const rule: Rule = marshallResource(item?.payload, 'rule');
  //       for (let [, policySet] of policySets) {
  //         for (let [, policy] of (policySet).combinables) {
  //           if (!_.isNil(policy) && policy.combinables.has(rule.id)) {
  //             _accessController.updateRule(policySet.id, policy.id, rule);
  //           }
  //         }
  //       }
  //     }
  //   }
  // }

  async getRules(ruleIDs?: string[]): Promise<Map<string, Rule>> {
    const filters = ruleIDs ? makeFilter(ruleIDs) : {};
    const result = await super.read(ReadRequest.fromPartial({ filters }), {});

    const rules = new Map<string, Rule>();
    if (result?.items) {
      _.forEach(result.items, (rule) => {
        if (rule?.payload?.id) {
          rules.set(rule.payload.id, marshallResource(rule.payload, 'rule'));
        }
      });
    }

    return rules;
  }

  async readMetaData(id?: string): Promise<DeepPartial<RuleListResponse>> {
    let result = await super.read(ReadRequest.fromPartial(
      {
        filters: [{
          filters: [{
            field: 'id',
            operation: Filter_Operation.eq,
            value: id
          }]
        }]
      }
    ), {});
    return result;
  }

  async superUpsert(request: RuleList, ctx: any): Promise<DeepPartial<RuleListResponse>> {
    const result = await super.upsert(request, ctx);
    // const policySets: Map<string, PolicySetWithCombinables> = await policySetService.load() || new Map();
    // this.policySets = policySets;
    return result;
  }

  async create(request: RuleList, ctx: any): Promise<DeepPartial<RuleListResponse>> {
    let subject = request.subject;
    // update meta data for owner information
    let items = request.items;
    items = await createMetadata(items, AuthZAction.CREATE, subject, this);

    let acsResponse: DecisionResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = items;
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'rule', id: items.map(item => item.id) }], AuthZAction.CREATE,
        Operation.isAllowed);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv for create Rules', { code: err.code, message: err.message, stack: err.stack });
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }

    if (acsResponse.decision != Response_Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    const result = await super.create(request, ctx);
    await this.reloadRules(result);
    return result;
  }

  async read(request: ReadRequest, ctx: any): Promise<DeepPartial<RuleListResponse>> {
    let subject = request.subject;;
    let acsResponse: PolicySetRQResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = [];
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'rule' }], AuthZAction.READ,
        Operation.whatIsAllowed) as PolicySetRQResponse;
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv for read Rules', { code: err.code, message: err.message, stack: err.stack });
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }
    if (acsResponse.decision != Response_Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    if (acsResponse?.custom_query_args?.length > 0) {
      request.custom_queries = acsResponse.custom_query_args[0].custom_queries;
      request.custom_arguments = acsResponse.custom_query_args[0].custom_arguments;
    }
    const result = await super.read(request, ctx);
    return result;
  }

  async update(request: RuleList, ctx: any): Promise<DeepPartial<RuleListResponse>> {
    let subject = request.subject;
    // update meta data for owner information
    let items = request.items;
    items = await createMetadata(items, AuthZAction.MODIFY, subject, this);

    let acsResponse: DecisionResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = items;
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'rule', id: items.map(item => item.id) }], AuthZAction.MODIFY,
        Operation.isAllowed);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv for update Rules', { code: err.code, message: err.message, stack: err.stack });
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }
    if (acsResponse.decision != Response_Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    const result = await super.update(request, ctx);
    await this.reloadRules(result);
    return result;
  }

  async upsert(request: RuleList, ctx: any): Promise<DeepPartial<RuleListResponse>> {
    let subject = request.subject;
    // update meta data for owner information
    let items = request.items;
    items = await createMetadata(items, AuthZAction.MODIFY, subject, this);

    let acsResponse: DecisionResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = items;
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'rule', id: items.map(item => item.id) }], AuthZAction.MODIFY,
        Operation.isAllowed);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv for upsert Rules', { code: err.code, message: err.message, stack: err.stack });
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }
    if (acsResponse.decision != Response_Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    const result = await this.superUpsert(request, ctx);
    return result;
  }

  async delete(request: DeleteRequest, ctx: any): Promise<DeepPartial<DeleteResponse>> {
    let resources = [];
    let subject = request.subject;
    let ruleIDs = request.ids;
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
    if (request.collection) {
      action = AuthZAction.DROP;
      resources = [{ collection: request.collection }];
    }

    let acsResponse: DecisionResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = resources;
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'rule', id: ruleIDs }], action,
        Operation.isAllowed);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv for delete Rules', { code: err.code, message: err.message, stack: err.stack });
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }
    if (acsResponse.decision != Response_Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    deleteResponse = await super.delete(request, ctx);
    if (request?.ids?.length > 0) {
      for (let id of request.ids) {
        for (let [, policySet] of _accessController.policySets) {
          for (let [, policy] of policySet.combinables) {
            if (policy?.combinables?.has(id)) {
              _accessController.removeRule(policySet.id, policy.id, id);
            }
          }
        }
      }
    } else if (request?.collection && request.collection === true) {
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
export class PolicyService extends ServiceBase<PolicyListResponse, PolicyList> implements IAccessControlResourceService<Policy>, PolicyServiceImplementation {
  ruleService: RuleService;
  cfg: any;
  redisClient: RedisClientType<any, any>;
  authZ: ACSAuthZ;
  constructor(logger: any, db: any, policyTopic: Topic, rulesTopic: Topic, cfg: any,
    redisClient: RedisClientType<any, any>, authZ: ACSAuthZ) {
    let resourceFieldConfig;
    if (cfg.get('fieldHandlers')) {
      resourceFieldConfig = cfg.get('fieldHandlers');
      resourceFieldConfig['bufferFields'] = resourceFieldConfig?.bufferFields?.users;
      if (cfg.get('fieldHandlers:timeStampFields')) {
        resourceFieldConfig['timeStampFields'] = [];
        for (let timeStampFiledConfig of cfg.get('fieldHandlers:timeStampFields')) {
          if (timeStampFiledConfig.entities.includes('policies')) {
            resourceFieldConfig['timeStampFields'].push(...timeStampFiledConfig.fields);
          }
        }
      }
    }
    super('policy', policyTopic, logger, new ResourcesAPIBase(db, 'policies', resourceFieldConfig), true);
    this.ruleService = new RuleService(this.logger, rulesTopic, db, cfg, redisClient, authZ);
    this.cfg = cfg;
    this.redisClient = redisClient;
    this.authZ = authZ;
  }

  /**
   * Load rules/policies and map them,
   */
  async load(): Promise<Map<string, PolicyWithCombinables>> {
    return this.getPolicies();
  }

  // async reloadPolicies(result: DeepPartial<PolicyListResponse>): Promise<void> {
  //   const policySets = _.cloneDeep(_accessController.policySets);
  //   if (result?.items?.length > 0) {
  //     for (let item of result.items) {
  //       for (let [, policySet] of policySets) {
  //         if (policySet.combinables.has(item.payload?.id)) {
  //           const policy: PolicyWithCombinables = marshallResource(item.payload, 'policy');

  //           if (_.has(item.payload, 'rules') && !_.isEmpty(item.payload.rules)) {
  //             policy.combinables = await ruleService.getRules(item.payload.rules);

  //             if (policy.combinables.size != item?.payload?.rules?.length) {
  //               for (let id of item.payload.rules) {
  //                 if (!policy.combinables.has(id)) {
  //                   policy.combinables.set(id, null);
  //                 }
  //               }
  //             }
  //           }
  //           _accessController.updatePolicy(policySet.id, policy);
  //         }
  //       }
  //     }
  //   }
  // }

  async superUpsert(request: PolicyList, ctx: any): Promise<DeepPartial<PolicyListResponse>> {
    const result = await super.upsert(request, ctx);
    await _accessController.loadPolicies();
    return result;
  }

  async create(request: PolicyList, ctx: any): Promise<DeepPartial<PolicyListResponse>> {
    let subject = request.subject;
    // update meta data for owner information
    let items = request.items;
    items = await createMetadata(items, AuthZAction.CREATE, subject, this);

    let acsResponse: DecisionResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = items;
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'policy', id: items.map(item => item.id) }], AuthZAction.CREATE,
        Operation.isAllowed);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv for create Policies', { code: err.code, message: err.message, stack: err.stack });
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }
    if (acsResponse.decision != Response_Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    const result = await super.create(request, ctx);
    await this.reloadPolicies(result);

    return result;
  }

  async readMetaData(id?: string): Promise<DeepPartial<PolicyListResponse>> {
    let result = await super.read(ReadRequest.fromPartial({
      filters: [{
        filters: [{
          field: 'id',
          operation: Filter_Operation.eq,
          value: id
        }]
      }]
    }), {});
    return result;
  }

  async read(request: ReadRequest, ctx: any): Promise<DeepPartial<PolicyListResponse>> {
    let subject = request.subject;
    let acsResponse: PolicySetRQResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = [];
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'policy' }], AuthZAction.READ,
        Operation.whatIsAllowed) as PolicySetRQResponse;
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv for read Policies', { code: err.code, message: err.message, stack: err.stack });
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }
    if (acsResponse.decision != Response_Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    if (acsResponse?.custom_query_args?.length > 0) {
      request.custom_queries = acsResponse.custom_query_args[0].custom_queries;
      request.custom_arguments = acsResponse.custom_query_args[0].custom_arguments;
    }
    const result = await super.read(request, ctx);
    return result;
  }

  async update(request: PolicyList, ctx: any): Promise<DeepPartial<PolicyListResponse>> {
    let subject = request.subject;
    // update meta data for owner information
    let items = request.items;
    items = await createMetadata(items, AuthZAction.MODIFY, subject, this);

    let acsResponse: DecisionResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = items;
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'policy', id: items.map(item => item.id) }], AuthZAction.MODIFY,
        Operation.isAllowed);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv for update Policies', { code: err.code, message: err.message, stack: err.stack });
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }
    if (acsResponse.decision != Response_Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    const result = await super.update(request, ctx);
    await this.reloadPolicies(result);
    return result;
  }

  async upsert(request: PolicyList, ctx: any): Promise<DeepPartial<PolicyListResponse>> {
    let subject = request.subject;
    // update meta data for owner information
    let items = request.items;
    items = await createMetadata(items, AuthZAction.MODIFY, subject, this);

    let acsResponse: DecisionResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = items;
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'policy', id: items.map(item => item.id) }], AuthZAction.MODIFY,
        Operation.isAllowed);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv for upsert Policies', { code: err.code, message: err.message, stack: err.stack });
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }
    if (acsResponse.decision != Response_Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    const result = await this.superUpsert(request, ctx);
    return result;
  }

  async getPolicies(policyIDs?: string[]): Promise<Map<string, PolicyWithCombinables>> {
    const filters = policyIDs ? makeFilter(policyIDs) : [];
    const result = await super.read(ReadRequest.fromPartial({ filters }), {});

    const policies = new Map<string, PolicyWithCombinables>();
    if (result?.items?.length > 0) {
      for (let i = 0; i < result.items.length; i += 1) {
        const policy: PolicyWithCombinables = marshallResource(result.items[i].payload, 'policy');

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

  async delete(request: DeleteRequest, ctx: any): Promise<DeepPartial<DeleteResponse>> {
    let resources = [];
    let subject = request.subject;
    let policyIDs = request.ids;
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
    if (request.collection) {
      action = AuthZAction.DROP;
      resources = [{ collection: request.collection }];
    }

    let acsResponse: DecisionResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = resources;
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'policy', id: policyIDs }], action,
        Operation.isAllowed);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv for delete Policies', { code: err.code, message: err.message, stack: err.stack });
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }
    if (acsResponse.decision != Response_Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    deleteResponse = await super.delete(request, ctx);

    if (request?.ids?.length > 0) {
      for (let id of request.ids) {
        for (let [, policySet] of _accessController.policySets) {
          if (policySet.combinables.has(id)) {
            _accessController.removePolicy(policySet.id, id);
          }
        }
      }
    } else if (request?.collection && request.collection === true) {
      for (let [, policySet] of _accessController.policySets) {
        policySet.combinables = new Map();
        _accessController.updatePolicySet(policySet);
      }
    }
    return deleteResponse;
  }
}

export class PolicySetService extends ServiceBase<PolicySetListResponse, PolicySetList> implements IAccessControlResourceService<PolicySet>, PolicySetServiceImplementation {
  cfg: any;
  redisClient: RedisClientType<any, any>;
  authZ: ACSAuthZ;
  constructor(logger: any, db: any, policySetTopic: Topic, cfg: any,
    redisClient: RedisClientType<any, any>, authZ: ACSAuthZ) {
    let resourceFieldConfig;
    if (cfg.get('fieldHandlers')) {
      resourceFieldConfig = cfg.get('fieldHandlers');
      resourceFieldConfig['bufferFields'] = resourceFieldConfig?.bufferFields?.users;
      if (cfg.get('fieldHandlers:timeStampFields')) {
        resourceFieldConfig['timeStampFields'] = [];
        for (let timeStampFiledConfig of cfg.get('fieldHandlers:timeStampFields')) {
          if (timeStampFiledConfig.entities.includes('policy_sets')) {
            resourceFieldConfig['timeStampFields'].push(...timeStampFiledConfig.fields);
          }
        }
      }
    }
    super('policy_set', policySetTopic, logger, new ResourcesAPIBase(db, 'policy_sets', resourceFieldConfig), true);
    this.cfg = cfg;
    this.redisClient = redisClient;
    this.authZ = authZ;
  }

  async readMetaData(id?: string): Promise<DeepPartial<PolicySetListResponse>> {
    let result = await super.read(ReadRequest.fromPartial({
      filters: [{
        filters: [{
          field: 'id',
          operation: Filter_Operation.eq,
          value: id
        }]
      }]
    }), {});
    return result;
  }

  /**
   * Load policy sets and map them to policies.
   */
  async load(): Promise<Map<string, PolicySet>> {
    const data = await super.read(ReadRequest.fromPartial({}), {});

    if (!data || !data.items || data.items.length == 0) {
      this.logger.warn('No policy sets retrieved from database');
      return;
    }

    const items = data?.items ? data.items : [];
    const policies = await policyService.load();
    const policySets = new Map<string, PolicySet>();

    for (let item of items) {
      if (!item?.payload?.policies) {
        this.logger.warn(`No policies were found for policy set ${item.payload.name}`);
        continue;
      }

      const policySet: PolicySetWithCombinables = marshallResource(item.payload, 'policy_set');

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

  async superUpsert(request: PolicySetList, context: any): Promise<DeepPartial<PolicySetListResponse>> {
    const result = await super.upsert(request, context);
    if (result?.items?.length > 0) {
      for (let item of result.items) {
        const policySet = marshallResource(item?.payload, 'policy_set');
        const policyIDs = item?.payload?.policies;
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

  async create(request: PolicySetList, ctx: any): Promise<DeepPartial<PolicySetListResponse>> {
    let subject = request.subject;
    // update meta data for owner information
    let items = request.items;
    items = await createMetadata(items, AuthZAction.CREATE, subject, this);

    let acsResponse: DecisionResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = items;
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'policy_set', id: items.map(item => item.id) }], AuthZAction.CREATE,
        Operation.isAllowed);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv for create PolicySets', { code: err.code, message: err.message, stack: err.stack });
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }
    if (acsResponse.decision != Response_Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    const result = await super.create(request, ctx);
    if (result?.items?.length > 0) {
      for (let item of result.items) {
        const policySet = marshallResource(item?.payload, 'policy_set');
        const policyIDs = item?.payload?.policies;
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

  async update(request: PolicySetList, ctx: any): Promise<DeepPartial<PolicySetListResponse>> {
    let subject = request.subject;
    // update meta data for owner information
    let items = request.items;
    items = await createMetadata(items, AuthZAction.MODIFY, subject, this);

    let acsResponse: DecisionResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = items;
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'policy_set', id: items.map(item => item.id) }], AuthZAction.MODIFY,
        Operation.isAllowed);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv for update PolicySets', { code: err.code, message: err.message, stack: err.stack });
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }
    if (acsResponse.decision != Response_Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    const result = await super.update(request, ctx);

    // update in memory policies if no exception was thrown
    for (let item of request?.items) {
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

  async delete(request: DeleteRequest, ctx: any): Promise<DeepPartial<DeleteResponse>> {
    let resources = [];
    let subject = request.subject;
    let policySetIDs = request.ids;
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
    if (request.collection) {
      action = AuthZAction.DROP;
      resources = [{ collection: request.collection }];
    }

    let acsResponse: DecisionResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = resources;
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'policy_set', id: policySetIDs }], action,
        Operation.isAllowed);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv for delete PolicySets', { code: err.code, message: err.message, stack: err.stack });
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }
    if (acsResponse.decision != Response_Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    deleteResponse = await super.delete(request, ctx);

    if (request?.ids?.length > 0) {
      for (let id of request.ids) {
        _accessController.removePolicySet(id);
      }
    } else if (request.collection && request.collection == true) {
      _accessController.clearPolicies();
    }
    return deleteResponse;
  }

  async read(request: ReadRequest, ctx: any): Promise<DeepPartial<PolicySetListResponse>> {
    let subject = request.subject;
    let acsResponse: PolicySetRQResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = [];
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'policy_set' }], AuthZAction.READ,
        Operation.whatIsAllowed) as PolicySetRQResponse;
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv for read PolicySets', { code: err.code, message: err.message, stack: err.stack });
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }
    if (acsResponse.decision != Response_Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    if (acsResponse?.custom_query_args?.length > 0) {
      request.custom_queries = acsResponse.custom_query_args[0].custom_queries;
      request.custom_arguments = acsResponse.custom_query_args[0].custom_arguments;
    }
    const result = await super.read(request, ctx);
    return result;
  }

  async upsert(request: PolicySetList, ctx: any): Promise<DeepPartial<PolicySetListResponse>> {
    let subject = request.subject;
    // update meta data for owner information
    let items = request.items;
    items = await createMetadata(items, AuthZAction.MODIFY, subject, this);

    let acsResponse: DecisionResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = items;
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'policy_set', id: items.map(item => item.id) }], AuthZAction.MODIFY,
        Operation.isAllowed);
    } catch (err) {
      this.logger.error('Error occurred requesting access-control-srv for upsert PolicySets', { code: err.code, message: err.message, stack: err.stack });
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }
    if (acsResponse.decision != Response_Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    const result = await this.superUpsert(request, ctx);
    return result;
  }
}

export class ResourceManager {

  cfg: any;
  logger: Logger;
  events: Events;
  db: any;
  redisClient: RedisClientType<any, any>;
  authZ: any;

  constructor(cfg: any, logger: Logger, events: Events, db: any,
    accessController: AccessController, redisClient: RedisClientType<any, any>, authZ: ACSAuthZ) {
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

  getResourceService(resource: string): RuleService | PolicyService | PolicySetService {
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
