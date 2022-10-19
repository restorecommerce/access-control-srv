import * as _ from 'lodash';
import * as chassis from '@restorecommerce/chassis-srv';
import { createLogger } from '@restorecommerce/logger';
import { Logger } from 'winston';
import { Events, registerProtoMeta } from '@restorecommerce/kafka-client';
import { AccessControlCommandInterface, AccessControlService } from './accessControlService';
import { ResourceManager } from './resourceManager';
import { createClient, RedisClientType } from 'redis';
import { Arango } from '@restorecommerce/chassis-srv/lib/database/provider/arango/base';

import * as core from './core';
import { ACSAuthZ, initAuthZ, initializeCache } from '@restorecommerce/acs-client';
import { createChannel, createClient as grpcCreateClient } from '@restorecommerce/grpc-client';
import {
  ServiceDefinition as UserServiceDefinition,
  ServiceClient as UserServiceClient, FindByTokenRequest
} from '@restorecommerce/rc-grpc-clients/dist/generated/io/restorecommerce/user';
import {
  ServiceDefinition as RuleServiceDefinition,
  protoMetadata as ruleMeta
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/rule';
import {
  ServiceDefinition as PolicyServiceDefinition,
  protoMetadata as policyMeta
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/policy';
import {
  ServiceDefinition as PolicySetServiceDefinition,
  protoMetadata as policySetMeta
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/policy_set';
import {
  ServiceDefinition as AccessControlServiceDefinition,
  protoMetadata as accessControlMeta
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/access_control';
import {
  ServiceDefinition as CommandInterfaceServiceDefinition,
  protoMetadata as commandInterfaceMeta
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/commandinterface';
import { protoMetadata as reflectionMeta } from '@restorecommerce/rc-grpc-clients/dist/generated-server/grpc/reflection/v1alpha/reflection';
import {
  HealthDefinition
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/grpc/health/v1/health';
import { BindConfig } from '@restorecommerce/chassis-srv/lib/microservice/transport/provider/grpc';

const capitalized = (collectionName: string): string => {
  const labels = collectionName.split('_').map((element) => {
    return element.charAt(0).toUpperCase() + element.substr(1);
  });
  return _.join(labels, '');
};

registerProtoMeta(ruleMeta, policyMeta, policySetMeta, accessControlMeta,
  commandInterfaceMeta, reflectionMeta);

/**
 * Generates Kafka configs for CRUD events.
 */
const genEventsConfig = (collectionName: string, cfg: any): any => {
  const servicePrefix = cfg.get('protosServicePrefix');

  const crudEvents = ['Created', 'Modified', 'Deleted'];

  const kafkaCfg = cfg.get('events:kafka');
  for (let event of crudEvents) {
    kafkaCfg[`${collectionName}${event}`] = {
      messageObject: `${servicePrefix}${collectionName}.${capitalized(collectionName)}`
    };
  }
  return kafkaCfg;
};

/**
 * Access Control Service
 */
export class Worker {
  cfg: any;
  logger: Logger;
  server: chassis.Server;
  events: Events;
  commandInterface: AccessControlCommandInterface;
  accessController: core.AccessController;
  redisClient: RedisClientType<any, any>;
  authZ: ACSAuthZ;
  offsetStore: chassis.OffsetStore;
  async start(cfg?: any, logger?: any): Promise<any> {
    this.cfg = cfg || await chassis.config.get();
    const loggerCfg = this.cfg.get('logger');
    loggerCfg.esTransformer = (msg) => {
      msg.fields = JSON.stringify(msg.fields);
      return msg;
    };
    this.logger = logger || createLogger(loggerCfg);

    this.logger.info('Starting access control service');
    const server = new chassis.Server(this.cfg.get('server'), this.logger);  // gRPC server

    let kafkaConfig = this.cfg.get('events:kafka');
    const policySetConfig = genEventsConfig('policy_set', this.cfg);
    const policyConfig = genEventsConfig('policy', this.cfg);
    let ruleConfig = genEventsConfig('rule', this.cfg);

    this.cfg.set('events:kafka',
      _.assign({}, kafkaConfig, policySetConfig, policyConfig, ruleConfig));

    kafkaConfig = this.cfg.get('events:kafka');
    const acsEvents = [
      'policy_setCreated',
      'policy_setModified',
      'policy_setDeleted',
      'policyCreated',
      'policyModified',
      'policyDeleted',
      'ruleCreated',
      'ruleModified',
      'ruleDeleted',
    ];
    const hierarchicalScopesResponse = 'hierarchicalScopesResponse';
    const events = new Events(kafkaConfig, this.logger); // Kafka
    await events.start();
    this.offsetStore = new chassis.OffsetStore(events, this.cfg, this.logger);

    // init Redis Client for subject index
    const redisConfig = this.cfg.get('redis');
    redisConfig.database = this.cfg.get('redis:db-indexes:db-subject');
    this.redisClient = createClient(redisConfig);
    this.redisClient.on('error', (err) => logger.error('Redis Client Error', { code: err.code, message: err.message, stack: err.stack }));
    await this.redisClient.connect();

    const userTopic = await events.topic(kafkaConfig.topics['user'].topic);
    // instantiate IDS client
    let userService: UserServiceClient;
    const grpcIDSConfig = this.cfg.get('client:user');
    if (grpcIDSConfig) {
      const channel = createChannel(grpcIDSConfig.address);
      userService = grpcCreateClient({
        ...grpcIDSConfig,
        logger
      }, UserServiceDefinition, channel);
    }
    this.accessController = new core.AccessController(this.logger,
      this.cfg.get('policies:options'), userTopic, this.cfg, userService);

    // resources
    const db = await chassis.database.get(this.cfg.get('database:main'), this.logger);
    // init ACS cache
    await initializeCache();
    // init AuthZ
    this.authZ = await initAuthZ(this.cfg) as ACSAuthZ;
    const resourceManager = new ResourceManager(this.cfg, this.logger, events, db,
      this.accessController, this.redisClient, this.authZ);
    await resourceManager.setup();
    await server.bind('io-restorecommerce-policy-set-srv', {
      service: PolicySetServiceDefinition,
      implementation: resourceManager.getResourceService('policy_set')
    } as BindConfig<PolicySetServiceDefinition>);
    // policy resource
    await server.bind('io-restorecommerce-policy-srv', {
      service: PolicyServiceDefinition,
      implementation: resourceManager.getResourceService('policy')
    } as BindConfig<PolicyServiceDefinition>);
    // policy resource
    await server.bind('io-restorecommerce-rule-srv', {
      service: RuleServiceDefinition,
      implementation: resourceManager.getResourceService('rule')
    } as BindConfig<RuleServiceDefinition>);
    // access control service
    const accessControlService = new AccessControlService(this.cfg, this.logger, resourceManager, this.accessController);
    await server.bind('io-restorecommerce-access-control-srv', {
      service: AccessControlServiceDefinition,
      implementation: accessControlService
    } as BindConfig<AccessControlServiceDefinition>);
    // command interface
    this.commandInterface = new AccessControlCommandInterface(server, this.cfg,
      this.logger, events, accessControlService, this.redisClient);
    await server.bind('io-restorecommerce-access-control-ci', {
      service: CommandInterfaceServiceDefinition,
      implementation: this.commandInterface
    } as BindConfig<CommandInterfaceServiceDefinition>);

    await server.bind('grpc-health-v1', {
      service: HealthDefinition,
      implementation: new chassis.Health(this.commandInterface, {
        readiness: async () => !!await ((db as Arango).db).version()
      })
    } as BindConfig<HealthDefinition>);

    this.events = events;
    this.server = server;
    await server.start();

    this.logger.info('Access control service started correctly!');
    this.logger.info('Loading resources...');
    await accessControlService.loadPolicies();

    const that = this;
    const commandTopic = await events.topic(this.cfg.get('events:kafka:topics:command:topic'));
    const eventListener = async (msg: any,
      context: any, config: any, eventName: string): Promise<any> => {
      if (acsEvents.indexOf(eventName) > -1) {
        await accessControlService.loadPolicies();
      } else if (eventName === hierarchicalScopesResponse) {
        // Add subject_id to waiting list
        const hierarchical_scopes = msg.hierarchical_scopes;
        const tokenDate = msg.token;
        // store HR scopes to cache with subjectID
        const subID = msg.subject_id;
        const token = tokenDate.split(':')[0];
        let redisHRScopesKey;
        let subject;
        if (token) {
          subject = await this.accessController.userService.findByToken(FindByTokenRequest.fromPartial({ token }));
          if (subject && subject.payload) {
            const tokens = subject.payload.tokens;
            const subID = subject.payload.id;
            const tokenFound = _.find(tokens, { token });
            if (tokenFound && tokenFound.interactive) {
              redisHRScopesKey = `cache:${subID}:hrScopes`;
            } else if (tokenFound && !tokenFound.interactive) {
              redisHRScopesKey = `cache:${subID}:${token}:hrScopes`;
            }

            let redisSubKey = `cache:${subID}:subject`;
            let redisSub;
            try {
              redisSub = await that.accessController.getRedisKey(redisSubKey);
              if (_.isEmpty(redisSub)) {
                await that.accessController.setRedisKey(redisSubKey, JSON.stringify(subject.payload));
              }
            } catch (err) {
              this.logger.error('Error retrieving Subject from redis in acs-srv');
            }
          }
        }

        try {
          await that.accessController.setRedisKey(redisHRScopesKey, JSON.stringify(hierarchical_scopes));
          that.logger.info(`HR scope saved successfully for Subject ${subID}`);
        } catch (err) {
          that.logger.info('Subject not persisted in redis for updating');
        }
        if (that.accessController.waiting[tokenDate]) {
          // clear timeout and resolve
          that.accessController.waiting[tokenDate].forEach(waiter => {
            clearTimeout(waiter.timeoutId);
            return waiter.resolve(true);
          });
          delete that.accessController.waiting[tokenDate];
        }
      } else if (eventName === 'userModified') {
        if (msg && 'id' in msg) {
          const updatedRoleAssocs = msg.role_associations;
          const updatedTokens = msg.tokens;
          let redisKey = `cache:${msg.id}:subject`;
          const redisSubject = await that.accessController.getRedisKey(redisKey);
          if (redisSubject) {
            const redisRoleAssocs = redisSubject.role_associations;
            const redisTokens = redisSubject.tokens;
            let roleAssocEqual;
            let tokensEqual;
            for (let userRoleAssoc of updatedRoleAssocs) {
              let found = false;
              for (let redisRoleAssoc of redisRoleAssocs) {
                if (redisRoleAssoc.role === userRoleAssoc.role) {
                  let i = 0;
                  const attrLenght = userRoleAssoc.attributes.length;
                  for (let redisAttribute of redisRoleAssoc.attributes) {
                    for (let userAttribute of userRoleAssoc.attributes) {
                      if (userAttribute.id === redisAttribute.id && userAttribute.value === redisAttribute.value) {
                        i++;
                      }
                    }
                  }
                  if (attrLenght === i) {
                    found = true;
                    roleAssocEqual = true;
                    break;
                  }
                }
              }
              if (!found) {
                that.logger.debug('Subject Role assocation has been updated', { userRoleAssoc });
                roleAssocEqual = false;
                break;
              }
            }
            // for interactive login after logout we receive userModified event
            // with empty tokens, so below check is not to evict cache for this case
            if (_.isEmpty(updatedTokens)) {
              tokensEqual = true;
            }
            for (let token of updatedTokens) {
              if (!token.interactive) {
                // compare only token scopes (since it now contains last_login as well)
                for (let redisToken of redisTokens) {
                  if (redisToken.token === token.token) {
                    tokensEqual = _.isEqual(redisToken.scopes.sort(), token.scopes.sort());
                  }
                }
                if (!tokensEqual) {
                  that.logger.debug('Subject Token scope has been updated', token);
                  break;
                }
              } else {
                tokensEqual = true;
              }
            }
            if (!roleAssocEqual || !tokensEqual || (updatedRoleAssocs.length != redisRoleAssocs.length)) {
              that.logger.info('Evicting HR scope for Subject', { id: msg.id });
              await that.accessController.evictHRScopes(msg.id); // flush HR scopes
              // TODO use tech user below once ACS check is implemented on chassis-srv for command-interface
              // Flush ACS Cache via flushCache Command
              const payload = {
                data: {
                  db_index: that.cfg.get('authorization:cache:db-index'),
                  pattern: msg.id
                }
              };
              const eventObject = {
                name: 'flush_cache',
                payload: {}
              };
              const eventPayload = Buffer.from(JSON.stringify(payload)).toString('base64');
              eventObject.payload = {
                type_url: 'payload',
                value: eventPayload
              };
              await commandTopic.emit('flushCacheCommand', eventObject);
              that.logger.info('ACS flush cache command event emitted to kafka topic successfully');
            }
          }
        }
      } else {
        await that.commandInterface.command(msg, context);
      }
    };

    for (let topicLabel in kafkaConfig.topics) {
      const topicCfg = kafkaConfig.topics[topicLabel];
      const topic = await events.topic(topicCfg.topic);
      const offSetValue = await this.offsetStore.getOffset(topicCfg.topic);
      if (topicCfg.events) {
        for (let eventName of topicCfg.events) {
          await topic.on(eventName, eventListener);
        }
      }
    }

    return accessControlService;
  }

  async stop(): Promise<void> {
    await this.events.stop();
    await this.server.stop();
    await this.offsetStore.stop();
    await this.redisClient.quit();
  }
}

if (require.main === module) {
  const worker = new Worker();
  worker.start().then().catch((err) => {
    console.error('startup error', err);
    process.exit(1);
  });

  process.on('SIGINT', () => {
    worker.stop().then().catch((err) => {
      console.error('shutdown error', err);
      process.exit(1);
    });
  });
}
