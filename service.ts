import * as _ from 'lodash';
import { Server } from '@restorecommerce/chassis-srv';
import { Events } from '@restorecommerce/kafka-client';

import { CommandInterface } from '@restorecommerce/chassis-srv';
import { ResourceManager } from './resourceManager';

import * as core from './core';

export class AccessControlService {
  cfg: any;
  logger: any;
  resourceManager: ResourceManager;
  accessController: core.AccessController;
  constructor(cfg: any, logger: any, resourceManager: ResourceManager, accessController: core.AccessController) {
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
    this.logger.info('Loading policies....');

    const policiesCfg = this.cfg.get('policies');
    const loadType = policiesCfg.type;
    switch (loadType) {
      case 'local':
        this.logger.silly('Loading policies from local files....');
        const path: string = policiesCfg.path;
        this.accessController = await core.utils.loadPoliciesFromDoc(this.accessController, path);
        break;
      case 'database':
        this.logger.silly('Loading policies from database....');
        const policySetService = this.resourceManager.getResourceService('policy_set');
        const policySets: Map<string, core.PolicySet> = await policySetService.load() || new Map();
        this.accessController.policySets = policySets;
        break;
    }
  }

  clearPolicies(): void {
    this.accessController.clearPolicies();
  }
  /**
   * gRPC interface
   */
  async isAllowed(call: any, context: any): Promise<core.Response> {
    const request = call.request;
    const acsRequest: core.Request = {
      target: request.target,
      context: request.context ? this.unmarshallContext(request.context) : {}
    };

    try {
      return this.accessController.isAllowed(acsRequest);
    } catch (err) { // deny if any error occurs
      return {
        decision: core.Decision.DENY,
        obligation: ''
      };
    }
  }

  async whatIsAllowed(call: any, context: any): Promise<any> {
    const request = call.request;
    const acsRequest: core.Request = {
      target: request.target,
      context: request.context ? this.unmarshallContext(request.context) : {}
    };
    return {
      policy_sets: this.accessController.whatIsAllowed(acsRequest)
    };
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
      this.logger.error('Error unmarshalling object', err.message);
      this.logger.verbose(err.stack);
      throw err;
    }
  }

}

export class AccessControlCommandInterface extends CommandInterface {
  accessControlService: AccessControlService;
  constructor(server: Server, cfg: any, logger: any, events: Events, accessControlService: AccessControlService) {
    super(server, cfg, logger, events);
    this.accessControlService = accessControlService;
  }

  async restore(payload: any): Promise<any> {
    const result = await super.restore(payload);

    this.accessControlService.clearPolicies();
    this.accessControlService.loadPolicies();
    return result;
  }

  async reset(): Promise<any> {
    const result = await super.reset();
    this.accessControlService.clearPolicies();
    return result;
  }
}
