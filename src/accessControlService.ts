import _ from 'lodash-es';
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

export class AccessControlService implements AccessControlServiceImplementation {
  cfg: any;
  logger: Logger;
  resourceManager: ResourceManager;
  accessController: AccessController;
  constructor(cfg: any, logger: Logger, resourceManager: ResourceManager, accessController: AccessController) {
    this.cfg = cfg;
    this.logger = logger;
    this.resourceManager = resourceManager;
    this.accessController = accessController;

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
    switch (loadType) {
      case 'local':
        const path: string = policiesCfg?.path;
        this.accessController = await loadPoliciesFromDoc(this.accessController, path);
        this.logger.silly('Policies from local files loaded');
        break;
      case 'database':
        const policySetService = this.resourceManager.getResourceService('policy_set');
        const policySets: Map<string, PolicySetWithCombinables> = await policySetService.load() || new Map();
        this.accessController.policySets = policySets;
        this.logger.silly('Policies from database loaded');
        break;
    }
  }

  clearPolicies(): void {
    this.accessController.clearPolicies();
  }
  /**
   * gRPC interface
   */
  async isAllowed(request: Request, context: any): Promise<DeepPartial<Response>> {
    const acsRequest: Request = {
      target: request.target,
      context: request.context ? this.unmarshallContext(request.context) : {}
    };

    try {
      return this.accessController.isAllowed(acsRequest);
    } catch (err) { // deny if any error occurs
      this.logger.error('Error evaluating isAllowed request', { code: err.code, message: err.message, stack: err.stack });
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
      context: request.context ? this.unmarshallContext(request.context) : {}
    };
    let whatisAllowedResponse: ReverseQuery;
    try {
      whatisAllowedResponse = await this.accessController.whatIsAllowed(acsRequest);
    } catch (err) {
      this.logger.error('Error evaluating whatIsAllowed request', { code: err.code, message: err.message, stack: err.stack });
      return {
        operation_status: {
          code: err.code,
          message: err.message
        }
      };
    }
    return whatisAllowedResponse;
  }

  unmarshallContext(context: any): any {
    for (let prop in context) {
      if (_.isArray(context[prop])) {
        context[prop] = _.map(context.resources, this.unmarshallProtobufAny.bind(this));
      } else {
        context[prop] = this.unmarshallProtobufAny(context[prop]);
      }
    }
    return context;
  }

  unmarshallProtobufAny(object: any): any {
    if (!object || _.isEmpty(object.value)) {
      return null;
    }

    try {
      return JSON.parse(object.value.toString());
    } catch (err) {
      this.logger.error('Error unmarshalling object', { code: err.code, message: err.message, stack: err.stack });
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
