import _ from 'lodash-es';
import * as chassis from '@restorecommerce/chassis-srv';
import { createLogger } from '@restorecommerce/logger';
import { Logger } from 'winston';
import { Events, registerProtoMeta } from '@restorecommerce/kafka-client';
import { AccessControlCommandInterface, AccessControlService } from './accessControlService.js';
import { ResourceManager } from './resourceManager.js';
import { createClient, RedisClientType } from 'redis';
import { Arango } from '@restorecommerce/chassis-srv/lib/database/provider/arango/base.js';
import { AccessController } from './core/accessController.js';
import { ACSAuthZ, initAuthZ, initializeCache } from '@restorecommerce/acs-client';
import { createChannel, createClient as grpcCreateClient } from '@restorecommerce/grpc-client';
import {
  FindByTokenRequest, UserServiceClient, UserServiceDefinition
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/user.js';
import {
  RoleAssociation
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/auth.js';
import {
  RuleServiceDefinition,
  protoMetadata as ruleMeta
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/rule.js';
import {
  PolicyServiceDefinition,
  protoMetadata as policyMeta
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/policy.js';
import {
  PolicySetServiceDefinition,
  protoMetadata as policySetMeta
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/policy_set.js';
import {
  AccessControlServiceDefinition,
  protoMetadata as accessControlMeta
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/access_control.js';
import {
  CommandInterfaceServiceDefinition,
  protoMetadata as commandInterfaceMeta
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/commandinterface.js';
import { protoMetadata as reflectionMeta } from '@restorecommerce/rc-grpc-clients/dist/generated-server/grpc/reflection/v1alpha/reflection.js';
import { protoMetadata as authMeta } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/auth.js';
import {
  protoMetadata as userMeta
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/user.js';
import {
  HealthDefinition
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/grpc/health/v1/health.js';
import { BindConfig } from '@restorecommerce/chassis-srv/lib/microservice/transport/provider/grpc/index.js';
import { compareRoleAssociations, flushACSCache } from './core/utils.js';
import * as fs from 'node:fs';
import yaml from 'js-yaml';

const capitalized = (collectionName: string): string => {
  const labels = collectionName.split('_').map((element) => {
    return element.charAt(0).toUpperCase() + element.substr(1);
  });
  return _.join(labels, '');
};

registerProtoMeta(ruleMeta, policyMeta, policySetMeta, accessControlMeta,
  commandInterfaceMeta, reflectionMeta, authMeta, userMeta);

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
  accessController: AccessController;
  redisClient: RedisClientType<any, any>;
  authZ: ACSAuthZ;
  offsetStore: chassis.OffsetStore;
  async start(cfg?: any, logger?: any): Promise<any> {
    this.cfg = cfg || await chassis.config.get();
    const loggerCfg = this.cfg.get('logger');
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
        logger: this.logger
      }, UserServiceDefinition, channel);
    }
    this.accessController = new AccessController(this.logger,
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

    // load seed policy_sets, policies and rules if it exists
    const seedDataConfig = this.cfg.get('seed_data');
    if (seedDataConfig) {
      const entities = Object.keys(seedDataConfig);
      for (let entity of entities) {
        const filePath = seedDataConfig[entity];
        await new Promise<void>((resolve, reject) => {
          fs.readFile(filePath, (err, data) => {
            if (err) {
              this.logger.error(`Failed loading seed ${entity} file`, err);
              reject(err);
              return;
            }

            let seedData;
            try {
              seedData = yaml.load(data, 'utf8');
            } catch (err) {
              this.logger.error(`Error parsing seed ${entity} file`, err);
              reject(err);
              return;
            }
            this.logger.info(`Loaded ${seedData?.length} seed ${entity}`);

            // get respective service object for upserting resource
            const service = resourceManager.getResourceService(entity);

            service.superUpsert({ items: seedData }, undefined)
              .then(() => {
                this.logger.info(`Seed ${entity} upserted successfully`);
                resolve();
              })
              .catch(err => {
                this.logger.error(`Failed upserting seed ${entity} file`, err);
                reject(err);
              });
          });
        }).catch((err) => {
          this.logger.error(`Failed upserting seed ${entity} file`, err);
        });;
      }
    }

    this.logger.info('Access control service started correctly!');
    await accessControlService.loadPolicies();

    const that = this;
    const commandTopic = await events.topic(this.cfg.get('events:kafka:topics:command:topic'));
    const eventListener = async (msg: any,
      context: any, config: any, eventName: string): Promise<any> => {
      if (acsEvents.indexOf(eventName) > -1) {
        await accessControlService.loadPolicies();
      } else if (eventName === hierarchicalScopesResponse) {
        // Add subject_id to waiting list
        const hierarchical_scopes = msg?.hierarchical_scopes ? msg.hierarchical_scopes : [];
        const tokenDate = msg?.token;
        // store HR scopes to cache with subjectID
        const subID = msg?.subject_id;
        const token = tokenDate?.split(':')[0];
        let redisHRScopesKey;
        let subject;
        if (token) {
          subject = await this.accessController.userService.findByToken(FindByTokenRequest.fromPartial({ token }));
          if (subject?.payload) {
            const tokens = subject.payload.tokens;
            const subID = subject.payload.id;
            const tokenFound = _.find(tokens, { token });
            if (tokenFound?.interactive) {
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
          const updatedRoleAssocs = msg.role_associations as RoleAssociation[];
          const updatedTokens = msg.tokens;
          let redisKey = `cache:${msg.id}:subject`;
          const redisSubject = await that.accessController.getRedisKey(redisKey);
          if (redisSubject) {
            const redisRoleAssocs = redisSubject.role_associations;
            const redisTokens = redisSubject.tokens;
            let roleAssocModified = compareRoleAssociations(updatedRoleAssocs, redisRoleAssocs, that.logger);
            let tokensEqual;
            // for interactive login after logout we receive userModified event
            // with empty tokens, so below check is not to evict cache for this case
            if (_.isEmpty(updatedTokens)) {
              tokensEqual = true;
            }
            for (let token of updatedTokens || []) {
              if (!token.interactive) {
                // compare only token scopes (since it now contains last_login as well)
                for (let redisToken of redisTokens || []) {
                  if (redisToken.token === token.token) {
                    tokensEqual = _.isEqual(redisToken?.scopes?.sort(), token?.scopes?.sort());
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
            if (roleAssocModified || !tokensEqual || (updatedRoleAssocs?.length != redisRoleAssocs?.length)) {
              that.logger.info('Evicting HR scope for Subject', { id: msg.id });
              await that.accessController.evictHRScopes(msg.id); // flush HR scopes
              // TODO use tech user below once ACS check is implemented on chassis-srv for command-interface
              // Flush ACS Cache via flushCache Command
              await flushACSCache(msg.id, that.cfg.get('authorization:cache:db-index'), commandTopic, that.logger);
            }
          }
        }
      } else if (eventName === 'userDeleted') {
        that.logger.info('Evicting HR scope for Subject', { id: msg.id });
        await that.accessController.evictHRScopes(msg.id); // flush HR scopes
        // delete ACS cache
        await flushACSCache(msg.id, that.cfg.get('authorization:cache:db-index'), commandTopic, that.logger);
      } else {
        await that.commandInterface.command(msg, context);
      }
    };

    for (let topicLabel in kafkaConfig.topics) {
      const topicCfg = kafkaConfig.topics[topicLabel];
      const topic = await events.topic(topicCfg.topic);
      const offSetValue = await this.offsetStore.getOffset(topicCfg.topic);
      that.logger.info('subscribing to topic with offset value', topicCfg.topic, offSetValue);
      if (topicCfg.events) {
        for (let eventName of topicCfg.events) {
          await topic.on(eventName, eventListener, { startingOffset: offSetValue });
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
