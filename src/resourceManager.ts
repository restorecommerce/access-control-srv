import * as _ from 'lodash-es';
import { ResourcesAPIBase, ServiceBase, ElementOf } from '@restorecommerce/resource-base-interface';
import { Topic, Events } from '@restorecommerce/kafka-client';
import { AccessController } from './core/accessController.js';
import { createMetadata, checkAccessRequest } from './core/utils.js';
import {
  AuthZAction,
  Operation,
  ACSAuthZ,
  DecisionResponse,
  PolicySetRQResponse,
  CtxResource,
} from '@restorecommerce/acs-client';
import { RedisClientType } from 'redis';
import { Logger } from '@restorecommerce/logger';
import {
  Response_Decision
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/access_control.js';
import {
  PolicySetServiceImplementation,
  PolicySetList, PolicySetListResponse, PolicySet
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/policy_set.js';
import {
  PolicyServiceImplementation,
  PolicyList, PolicyListResponse
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/policy.js';
import { 
  ReadRequest,
  Filter_Operation,
  DeepPartial,
  DeleteRequest,
  DeleteResponse,
  ResourceList,
  ResourceListResponse,
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/resource_base.js';
import { PolicyWithCombinables, PolicySetWithCombinables } from './core/interfaces.js';
import { makeFilter, marshallResource, Seedable } from './core/services/utils.js';
import { OwnershipDomainService } from './core/services/ownershipDomainService.js';
import { RuleService } from './core/services/ruleService.js';
import { CallContext } from '@restorecommerce/grpc-client';
import { ServiceConfig } from '@restorecommerce/service-config';
import { DatabaseProvider } from '@restorecommerce/chassis-srv';

export interface IAccessControlResourceService<O extends ResourceListResponse, I extends ResourceList>
  extends Seedable<I>
{
  load(): Promise<Map<string, ElementOf<I['items']>>>;
  readMetaData(id?: string): Promise<DeepPartial<O>>;
}

/**
 * Policy resource service.
 */
export class PolicyService extends ServiceBase<PolicyListResponse, PolicyList>
  implements IAccessControlResourceService<PolicyListResponse, PolicyList>, PolicyServiceImplementation
{
  constructor(
    readonly logger: Logger,
    policyTopic: Topic,
    cfg: ServiceConfig,
    private readonly resourceManager: ResourceManager,
    private readonly accessController = resourceManager.accessController,
  ) {
    let resourceFieldConfig;
    if (cfg.get('fieldHandlers')) {
      resourceFieldConfig = cfg.get('fieldHandlers');
      resourceFieldConfig['bufferFields'] = resourceFieldConfig?.bufferFields?.users;
      if (cfg.get('fieldHandlers:timeStampFields')) {
        resourceFieldConfig['timeStampFields'] = [];
        for (const timeStampFiledConfig of cfg.get('fieldHandlers:timeStampFields')) {
          if (timeStampFiledConfig.entities.includes('policies')) {
            resourceFieldConfig['timeStampFields'].push(...timeStampFiledConfig.fields);
          }
        }
      }
    }
    super(
      'policy',
      policyTopic,
      logger,
      new ResourcesAPIBase(
        resourceManager.db,
        'policies',
        resourceFieldConfig,
        undefined,
        undefined,
        logger,
        'policy',
      ),
      true
    );
  }

  /**
   * Load rules/policies and map them,
   */
  async load(): Promise<Map<string, PolicyWithCombinables>> {
    return this.getPolicies();
  }

  async insertSeed(request: PolicyList, ctx?: any): Promise<void> {
    const ruleService = this.resourceManager.getResourceService('rule');
    const result = await super.upsert(request, ctx);
    const policySets = _.cloneDeep(this.accessController.policySets);

    if (result?.items?.length > 0) {
      for (const item of result.items) {
        for (const [, policySet] of policySets) {
          if (policySet.combinables.has(item.payload?.id)) {
            const policy: PolicyWithCombinables = marshallResource(item.payload, 'policy');

            if (_.has(item.payload, 'rules') && !_.isEmpty(item.payload.rules)) {
              policy.combinables = await ruleService.getRules(item.payload.rules);

              if (policy.combinables.size != item?.payload?.rules?.length) {
                for (const id of item.payload.rules) {
                  if (!policy.combinables.has(id)) {
                    policy.combinables.set(id, null);
                  }
                }
              }
            }
            this.accessController.updatePolicy(policySet.id, policy);
          }
        }
      }
    }
  }

  async create(request: PolicyList, ctx?: any): Promise<DeepPartial<PolicyListResponse>> {
    const ruleService = this.resourceManager.getResourceService('rule');
    const subject = request.subject;
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
    } catch (err: any) {
      this.logger.error('Error occurred requesting access-control-srv for create Policies', err);
      return {
        operation_status: {
          code: Number.isInteger(err.code) ? err.code : 500,
          message: err.message
        }
      };
    }
    if (acsResponse.decision != Response_Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    const result = await super.create(request, ctx);
    const policySets = _.cloneDeep(this.accessController.policySets);

    if (result?.items?.length > 0) {
      for (const item of result.items) {
        for (const [, policySet] of policySets) {
          if (policySet.combinables.has(item.payload?.id)) {
            const policy: PolicyWithCombinables = marshallResource(item.payload, 'policy');

            if (_.has(item.payload, 'rules') && !_.isEmpty(item.payload.rules)) {
              policy.combinables = await ruleService.getRules(item.payload.rules);

              if (policy.combinables.size != item?.payload?.rules?.length) {
                for (const id of item.payload.rules) {
                  if (!policy.combinables.has(id)) {
                    policy.combinables.set(id, null);
                  }
                }
              }
            }
            this.accessController.updatePolicy(policySet.id, policy);
          }
        }
      }
    }

    return result;
  }

  async readMetaData(id?: string): Promise<DeepPartial<PolicyListResponse>> {
    const result = await super.read(ReadRequest.fromPartial({
      filters: [{
        filters: [{
          field: 'id',
          operation: Filter_Operation.eq,
          value: id
        }]
      }]
    }), {} as any);
    return result;
  }

  async read(request: ReadRequest, ctx?: any): Promise<DeepPartial<PolicyListResponse>> {
    const subject = request.subject;
    let acsResponse: PolicySetRQResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = [];
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'policy' }], AuthZAction.READ,
        Operation.whatIsAllowed) as PolicySetRQResponse;
    } catch (err: any) {
      this.logger.error('Error occurred requesting access-control-srv for read Policies', err);
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

  async update(request: PolicyList, ctx?: any): Promise<DeepPartial<PolicyListResponse>> {
    const policySetService = this.resourceManager.getResourceService('policy_set');
    const subject = request.subject;
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
    } catch (err: any) {
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
    this.accessController.policySets = await policySetService.load() || new Map();
    this.logger.info('Reloaded Policies after update operation');
    return result;
  }

  async upsert(request: PolicyList, ctx?: any): Promise<DeepPartial<PolicyListResponse>> {
    const policySetService = this.resourceManager.getResourceService('policy_set');
    const subject = request.subject;
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
    } catch (err: any) {
      this.logger.error('Error occurred requesting access-control-srv for upsert Policies', err);
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
    const result = await super.upsert(request, ctx);
    this.resourceManager.accessController.policySets = await policySetService.load() || new Map();
    this.logger.info('Reloaded Policies after upsert operation');
    return result;
  }

  async getPolicies(policyIDs?: string[]): Promise<Map<string, PolicyWithCombinables>> {
    const ruleService = this.resourceManager.getResourceService('rule');
    const filters = policyIDs ? makeFilter(policyIDs) : [];
    const result = await super.read(ReadRequest.fromPartial({ filters }), {} as any);

    const policies = new Map<string, PolicyWithCombinables>();
    if (result?.items?.length > 0) {
      for (let i = 0; i < result.items.length; i += 1) {
        const policy: PolicyWithCombinables = marshallResource(result.items[i].payload, 'policy');

        if (!_.isEmpty(result.items[i]?.payload?.rules)) {
          policy.combinables = await ruleService.getRules(result.items[i].payload.rules);
          if (policy.combinables.size != result.items[i].payload.rules.length) {
            for (const ruleID of result.items[i].payload.rules) {
              const ruleData = await ruleService.getRules([ruleID]);
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

  async delete(request: DeleteRequest, ctx?: any): Promise<DeepPartial<DeleteResponse>> {
    const resources = new Array<CtxResource>();
    const subject = request.subject;
    const policyIDs = request.ids;
    let action;
    if (request.collection) {
      action = AuthZAction.DROP;
      resources.push({ collection: request.collection });
    }
    else if (policyIDs) {
      action = AuthZAction.DELETE;
      if (Array.isArray(policyIDs)) {
        resources.push(...policyIDs.map(id => ({id})));
      } else {
        resources.push({ id: policyIDs });
      }
      Object.assign(resources, { id: policyIDs });
      await createMetadata(resources, action, subject, this);
    }

    let acsResponse: DecisionResponse;
    try {
      ctx ??= {};
      ctx.subject = subject;
      ctx.resources = resources;
      acsResponse = await checkAccessRequest(
        ctx,
        [{ resource: 'policy', id: policyIDs }],
        action,
        Operation.isAllowed
      );
    }
    catch (err: any) {
      const { code, message, stack } = err;
      this.logger.error('Error occurred requesting access-control-srv for delete Policies', { code, message, stack });
      return {
        operation_status: {
          code: Number.isInteger(code) ? code : 500,
          message
        }
      };
    }
    if (acsResponse.decision != Response_Decision.PERMIT) {
      return { operation_status: acsResponse.operation_status };
    }
    const deleteResponse = await super.delete(request, ctx);

    if (request?.ids?.length > 0) {
      for (const id of request.ids) {
        for (const [, policySet] of this.accessController.policySets) {
          if (policySet.combinables.has(id)) {
            this.accessController.removePolicy(policySet.id, id);
          }
        }
      }
    } else if (request?.collection && request.collection === true) {
      for (const [, policySet] of this.accessController.policySets) {
        policySet.combinables = new Map();
        this.accessController.updatePolicySet(policySet);
      }
    }
    return deleteResponse;
  }

  async insertSeedData(request: PolicyList, context?: CallContext): Promise<void> {
    super.upsert(request, context);
  }
}

export class PolicySetService
  extends ServiceBase<PolicySetListResponse, PolicySetList>
  implements IAccessControlResourceService<PolicySetListResponse, PolicySetList>, PolicySetServiceImplementation
{
  constructor(
    readonly logger: Logger,
    readonly policySetTopic: Topic,
    readonly cfg: ServiceConfig,
    readonly resourceManager: ResourceManager,
  ) {
    let resourceFieldConfig;
    if (cfg.get('fieldHandlers')) {
      resourceFieldConfig = cfg.get('fieldHandlers');
      resourceFieldConfig['bufferFields'] = resourceFieldConfig?.bufferFields?.users;
      if (cfg.get('fieldHandlers:timeStampFields')) {
        resourceFieldConfig['timeStampFields'] = [];
        for (const timeStampFiledConfig of cfg.get('fieldHandlers:timeStampFields')) {
          if (timeStampFiledConfig.entities.includes('policy_sets')) {
            resourceFieldConfig['timeStampFields'].push(...timeStampFiledConfig.fields);
          }
        }
      }
    }
    super(
      'policy_set',
      policySetTopic,
      logger,
      new ResourcesAPIBase(
        resourceManager.db,
        'policy_sets',
        resourceFieldConfig,
        undefined,
        undefined,
        logger,
        'policy_set',
      ),
      true
    );
  }

  async readMetaData(id?: string): Promise<DeepPartial<PolicySetListResponse>> {
    const result = await super.read(ReadRequest.fromPartial({
      filters: [{
        filters: [{
          field: 'id',
          operation: Filter_Operation.eq,
          value: id
        }]
      }]
    }), {} as any);
    return result;
  }

  /**
   * Load policy sets and map them to policies.
   */
  async load(): Promise<Map<string, PolicySet>> {
    const policyService = this.resourceManager.getResourceService('policy');
    const data = await super.read(ReadRequest.fromPartial({}), {} as any);

    if (!data || !data.items || data.items.length == 0) {
      this.logger.warn('No policy sets retrieved from database');
      return;
    }

    const items = data?.items ? data.items : [];
    const policies = await policyService.load();
    const policySets = new Map<string, PolicySet>();

    for (const item of items) {
      if (!item?.payload?.policies) {
        this.logger.warn(`No policies were found for policy set ${item.payload.name}`);
        continue;
      }

      const policySet: PolicySetWithCombinables = marshallResource(item.payload, 'policy_set');

      _.forEach(item.payload.policies, (policyID: string) => {
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

  async insertSeed(request: PolicySetList, context: any): Promise<void> {
    const policyService = this.resourceManager.getResourceService('policy');
    const result = await super.upsert(request, context);
    if (result?.items?.length > 0) {
      for (const item of result.items) {
        const policySet = marshallResource(item?.payload, 'policy_set');
        const policyIDs = item?.payload?.policies;
        if (!_.isEmpty(policyIDs)) {
          policySet.combinables = await policyService.getPolicies(policyIDs);
          if (policySet.combinables.size != policyIDs.length) {
            for (const id of policyIDs) {
              if (!policySet.combinables.has(id)) {
                policySet.combinables.set(id, null);
              }
            }
          }
        }
        this.resourceManager.accessController.updatePolicySet(policySet);
      }
    }
  }

  async create(request: PolicySetList, ctx: any): Promise<DeepPartial<PolicySetListResponse>> {
    const policyService = this.resourceManager.getResourceService('policy');
    const subject = request.subject;
    // update meta data for owner information
    let items = request.items;
    items = await createMetadata(items, AuthZAction.CREATE, subject, this);

    let acsResponse: DecisionResponse;
    try {
      if (!ctx) { ctx = {}; }
      ctx.subject = subject;
      ctx.resources = items;
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'policy_set', id: items.map(item => item.id) }], AuthZAction.CREATE,
        Operation.isAllowed);
    } catch (err: any) {
      this.logger.error('Error occurred requesting access-control-srv for create PolicySets', err);
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
      for (const item of result.items) {
        const policySet = marshallResource(item?.payload, 'policy_set');
        const policyIDs = item?.payload?.policies;
        if (!_.isEmpty(policyIDs)) {
          policySet.combinables = await policyService.getPolicies(policyIDs);
          if (policySet.combinables.size != policyIDs.length) {
            for (const id of policyIDs) {
              if (!policySet.combinables.has(id)) {
                policySet.combinables.set(id, null);
              }
            }
          }
        }
        this.resourceManager.accessController.updatePolicySet(policySet);
      }
    }

    return result;
  }

  async update(request: PolicySetList, ctx: any): Promise<DeepPartial<PolicySetListResponse>> {
    const policyService = this.resourceManager.getResourceService('policy');
    const subject = request.subject;
    // update meta data for owner information
    let items = request.items;
    items = await createMetadata(items, AuthZAction.MODIFY, subject, this);

    let acsResponse: DecisionResponse;
    try {
      if (!ctx) { ctx = {}; }
      ctx.subject = subject;
      ctx.resources = items;
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'policy_set', id: items.map(item => item.id) }], AuthZAction.MODIFY,
        Operation.isAllowed);
    } catch (err: any) {
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
    const reqItems = request?.items;
    for (const item of reqItems) {
      let policySet = this.resourceManager.accessController.policySets.get(item.id);
      let policies = policySet.combinables;

      if (_.has(item, 'policies')) {
        for (const [policyID, policy] of policies) {
          if (_.indexOf(item.policies, policyID) == -1) {
            policies.delete(policyID);
          }
        }

        const missingIDs: string[] = [];
        for (const policyID of item.policies) {
          if (!policySet.combinables.has(policyID)) {
            missingIDs.push(policyID);
          }
        }

        if (!_.isEmpty(missingIDs.length)) {
          const newPolicies = await policyService.getPolicies(missingIDs);
          if (newPolicies.size != missingIDs.length) {  // checking for non-existing policies in DB
            for (const id of missingIDs) {
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
      this.resourceManager.accessController.policySets.set(policySet.id, policySet);
    }

    return result;
  }

  async delete(request: DeleteRequest, ctx?: any): Promise<DeepPartial<DeleteResponse>> {
    let resources = new Array<ElementOf<CtxResource['items']>>;
    const subject = request.subject;
    const policySetIDs = request.ids;
    let action;
    if (policySetIDs) {
      action = AuthZAction.DELETE;
      if (Array.isArray(policySetIDs)) {
        for (const id of policySetIDs) {
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
    } catch (err: any) {
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
    const deleteResponse = await super.delete(request, ctx);

    if (request?.ids?.length > 0) {
      for (const id of request.ids) {
        this.resourceManager.accessController.removePolicySet(id);
      }
    } else if (request.collection && request.collection == true) {
      this.resourceManager.accessController.clearPolicies();
    }
    return deleteResponse;
  }

  async read(request: ReadRequest, ctx: any): Promise<DeepPartial<PolicySetListResponse>> {
    const subject = request.subject;
    let acsResponse: PolicySetRQResponse;
    try {
      if (!ctx) { ctx = {}; };
      ctx.subject = subject;
      ctx.resources = [];
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'policy_set' }], AuthZAction.READ,
        Operation.whatIsAllowed) as PolicySetRQResponse;
    } catch (err: any) {
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
    const policySetService = this.resourceManager.getResourceService('policy_set');
    const subject = request.subject;
    // update meta data for owner information
    let items = request.items;
    items = await createMetadata(items, AuthZAction.MODIFY, subject, this);

    let acsResponse: DecisionResponse;
    try {
      if (!ctx) { ctx = {}; }
      ctx.subject = subject;
      ctx.resources = items;
      acsResponse = await checkAccessRequest(ctx, [{ resource: 'policy_set', id: items.map(item => item.id) }], AuthZAction.MODIFY,
        Operation.isAllowed);
    } catch (err: any) {
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
    const result = await super.upsert(request, ctx);
    this.resourceManager.accessController.policySets = await policySetService.load() || new Map();
    this.logger.info('Reloaded PolicySet after upsert operation');
    return result;
  }

  async insertSeedData(request: PolicySetList, context?: CallContext): Promise<void> {
    super.upsert(request, context);
  }
}

export type ServiceMap = {
  policy_set: PolicySetService;
  policy: PolicyService;
  rule: RuleService;
  ownership_domain: OwnershipDomainService;
};
export type ServiceName = keyof ServiceMap;

export class ResourceManager {
  private serviceMap: ServiceMap;

  public static async setup(
    cfg: ServiceConfig,
    logger: Logger,
    events: Events,
    db: DatabaseProvider,
    accessController: AccessController,
    redisClient: RedisClientType<any, any>,
  ): Promise<ResourceManager> {
    return await new ResourceManager(cfg, logger, events, db, accessController, redisClient).setup();
  }

  protected constructor(
    readonly cfg: ServiceConfig,
    readonly logger: Logger,
    readonly events: Events,
    readonly db: DatabaseProvider,
    readonly accessController: AccessController,
    readonly redisClient: RedisClientType<any, any>
  ) {}

  protected async setup(): Promise<ResourceManager> {
    const kafkaCfg = this.cfg.get('events:kafka');
    const rulesTopic = await this.events.topic(kafkaCfg.topics['rule.resource'].topic);
    const policyTopic = await this.events.topic(kafkaCfg.topics['policy.resource'].topic);
    const policySetTopic = await this.events.topic(kafkaCfg.topics['policy_set.resource'].topic);
    const ownershipDomainTopic = await this.events.topic(kafkaCfg.topics['ownership_domain.resource'].topic);
    this.serviceMap = {
      policy_set: new PolicySetService(this.logger, policySetTopic, this.cfg, this),
      policy: new PolicyService(this.logger, policyTopic, this.cfg, this),
      rule: new RuleService(this.logger, rulesTopic, this.db, this.cfg, this.accessController),
      ownership_domain: new OwnershipDomainService(this.logger, ownershipDomainTopic, this.db, this.cfg),
    };
    return this;
  }

  getResourceService<T extends ServiceName>(resource: T): ServiceMap[T] {
    const service = this.serviceMap[resource];
    if (service) {
      return service as ServiceMap[T];
    }
    else {
      throw new Error(`Unknown resource ${resource}`);
    }
  }
}
