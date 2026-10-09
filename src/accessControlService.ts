import * as _ from 'lodash-es';
import { Server } from '@restorecommerce/chassis-srv';
import { Events } from '@restorecommerce/kafka-client';
import { CommandInterface } from '@restorecommerce/chassis-srv';
import { ResourceManager } from './resourceManager.js';
import { RedisClientType } from 'redis';
import { AccessController } from './core/accessController.js';
import { loadPoliciesFromDoc } from './core/utils.js';
import { Logger } from 'winston';
import {
  AccessControlServiceImplementation, ReverseQuery,
  Request, Response, DeepPartial, Response_Decision
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/access_control.js';
import {
  CommandInterfaceServiceImplementation
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/commandinterface.js';
import { PolicySetWithCombinables } from './core/interfaces.js';
import { OwnershipDomainService } from './core/services/ownershipDomainService.js';
import { Attribute } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/attribute.js';
import { urns } from '@restorecommerce/acs-client';


export class AccessControlService implements AccessControlServiceImplementation {
  cfg: any;
  logger: Logger;
  resourceManager: ResourceManager;
  accessController: AccessController;
  ownerDomainURN: string;

  constructor(cfg: any, logger: Logger, resourceManager: ResourceManager, accessController: AccessController) {
    this.cfg = cfg;
    this.logger = logger;
    this.resourceManager = resourceManager;
    this.accessController = accessController;
    this.ownerDomainURN = (urns as any).ownershipDomain;

    // create a resource adapter if any is defined in the config
    const adapterCfg = this.cfg.get('adapter') || {};
    if (!_.isEmpty(adapterCfg)) {
      this.accessController.createResourceAdapter(adapterCfg);
    }
  }
  async loadPolicies(): Promise<void> {
    this.logger.info('Loading policies');

    const policiesCfg = this.cfg.get('policies');
    const loadType = policiesCfg?.type;
    const path: string = policiesCfg?.path;
    const policySetService = this.resourceManager.getResourceService('policy_set');
    const policySets: Map<string, PolicySetWithCombinables> = await policySetService.load() || new Map();
    switch (loadType) {
      case 'local':
        this.accessController = await loadPoliciesFromDoc(this.accessController, path);
        this.logger.silly('Policies from local files loaded');
        break;
      case 'database':
        this.accessController.policySets = policySets;
        this.logger.silly('Policies from database loaded');
        break;
    }
  }

  clearPolicies(): void {
    this.accessController.clearPolicies();
  }

  /**
   * Resolve owner/acl attributes for every resource in context.resources.
   */
  private async resolveResourceOwnership(resources: any[], subject?: any): Promise<any[]> {
    if (!resources?.length) {
      return resources;
    }

    // 1. collect all referenced OwnershipDomain IDs
    const domainIDs = new Set<string>();
    for (const resource of resources) {
      for (const attr of [...(resource?.meta?.owners ?? []), ...(resource?.meta?.acls ?? [])]) {
        if (attr?.id === this.ownerDomainURN && attr.value) {
          domainIDs.add(attr.value);
        }
      }
    }
    if (!domainIDs.size) {
      return resources;
    }

    // 2. read all domains at once and put them into a Map
    const domains = new Map<string, Attribute[]>();
    const ownershipDomainService = this.resourceManager.getResourceService('ownership_domain') as OwnershipDomainService;
    try {
      const result = await ownershipDomainService.get([...domainIDs], subject);
      for (const item of result?.items ?? []) {
        if (item?.payload?.id) {
          domains.set(item.payload.id, item.payload.attributes ?? []);
        }
      }
    } catch (err: any) {
      // fail-closed: nothing resolved, resources fall out of scope
      this.logger.error('Error resolving OwnershipDomains', err);
    }

    // 3. append resolved attributes (reference stays in place)
    const append = (list?: Attribute[]): Attribute[] | undefined => {
      if (!list?.length) return list;
      const result = [...list];
      for (const attr of list) {
        if (attr?.id !== this.ownerDomainURN) continue;
        const resolved = domains.get(attr.value);
        if (resolved) {
          result.push(...resolved);
        } else {
          // 4. warn about missing / unreadable domains
          this.logger.warn('OwnershipDomain not found or not readable', { ownershipDomainId: attr.value });
        }
      }
      return result;
    };

    for (const resource of resources) {
      if (!resource?.meta) continue;
      resource.meta.owners = append(resource.meta.owners);
      resource.meta.acls = append(resource.meta.acls);
    }
    return resources;
  }

  /**
   * Resolve OwnershipDomain references within a single meta.owners / meta.acls
   * attribute list, replacing each reference with the domain's own attributes.
   */
  private async resolveOwnerAttributes(attributes: Attribute[]): Promise<Attribute[]> {
    if (!attributes?.length) {
      return attributes;
    }

    const hasOwnerRefs = attributes.some(attr => attr?.id === this.ownerDomainURN);
    if (!hasOwnerRefs) {
      return attributes;
    }

    const ownershipDomainService: OwnershipDomainService =
      this.resourceManager.getResourceService('ownership_domain') as OwnershipDomainService;

    const resolved: Attribute[] = [];
    for (const attr of attributes) {
      if (attr?.id !== this.ownerDomainURN) {
        resolved.push(attr);
        continue;
      }
      try {
        const result = await ownershipDomainService.get([attr.value], undefined, undefined, true);
        const domainAttributes = result?.items?.[0]?.payload?.attributes ?? [];
        resolved.push(...domainAttributes);
      } catch (err: any) {
        this.logger.error('Error resolving OwnershipDomain', err);
      }
    }
    return resolved;
  }

  private async parseContext(context: any): Promise<any> {
    for (const prop in context) {
      if (_.isArray(context[prop])) {
        context[prop] = _.map(context[prop], this.unmarshallProtobufAny.bind(this));
      } else {
        context[prop] = this.unmarshallProtobufAny(context[prop]);
      }
    }

    if (context?.resources?.length) {
      context.resources = await this.resolveResourceOwnership(context.resources);
    }

    return context;
  }

  async isAllowed(request: Request, context: any): Promise<DeepPartial<Response>> {
    const acsRequest: Request = {
      target: request.target,
      context: request.context ? await this.parseContext(request.context) : {}
    };

    try {
      return this.accessController.isAllowed(acsRequest);
    } catch (err: any) {
      this.logger.error('Error evaluating isAllowed request', err);
      return {
        decision: Response_Decision.DENY,
        obligations: [],
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }
  }

  async whatIsAllowed(request: Request, context: any): Promise<DeepPartial<ReverseQuery>> {
    const acsRequest: Request = {
      target: request.target,
      context: request.context ? await this.parseContext(request.context) : {}
    };

    let whatisAllowedResponse: ReverseQuery;
    try {
      whatisAllowedResponse = await this.accessController.whatIsAllowed(acsRequest);
    } catch (err: any) {
      this.logger.error('Error evaluating whatIsAllowed request', err);
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }
    return whatisAllowedResponse;
  }

  unmarshallProtobufAny(object: any): any {
    // unverändert — bleibt reines Buffer→Object-Parsing
    if (!object || _.isEmpty(object.value)) {
      return null;
    }
    try {
      return JSON.parse(object.value.toString());
    } catch (err: any) {
      this.logger.error('Error unmarshalling object', err);
      throw err;
    }
  }
}


export class AccessControlCommandInterface extends CommandInterface implements CommandInterfaceServiceImplementation {
  accessControlService: AccessControlService;
  constructor(server: Server, cfg: any, logger: Logger, events: Events,
    accessControlService: AccessControlService, redisClient: RedisClientType<any, any>) {
    super(server, cfg, logger, events, redisClient);
    this.accessControlService = accessControlService;
  }

  async restore(payload: any): Promise<any> {
    const result = await super.restore(payload);

    this.accessControlService.clearPolicies();
    await this.accessControlService.loadPolicies();
    return result;
  }

  async reset(): Promise<any> {
    const result = await super.reset();
    this.accessControlService.clearPolicies();
    return result;
  }
}
