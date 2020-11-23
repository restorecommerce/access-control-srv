import * as _ from 'lodash';
import * as chassis from '@restorecommerce/chassis-srv';
import { createLogger } from '@restorecommerce/logger';
import { Events } from '@restorecommerce/kafka-client';
import { AccessControlService, AccessControlCommandInterface } from './accessControlService';
import { ResourceManager } from './resourceManager';
import { RedisClient, createClient } from 'redis';
import { Arango } from '@restorecommerce/chassis-srv/lib/database/provider/arango/base';

import * as core from './core';
import { initAuthZ, ACSAuthZ, initializeCache } from '@restorecommerce/acs-client';
import { Client } from '@restorecommerce/grpc-client';

const capitalized = (collectionName: string): string => {
  const labels = collectionName.split('_').map((element) => {
    return element.charAt(0).toUpperCase() + element.substr(1);
  });
  return _.join(labels, '');
};

/**
 * Generates Kafka configs for CRUD events.
 */
const genEventsConfig = (collectionName: string, cfg: any): any => {
  const pathPrefix = cfg.get('protosPathPrefix');
  const servicePrefix = cfg.get('protosServicePrefix');
  const root = cfg.get('protosRoot');

  const crudEvents = ['Created', 'Modified', 'Deleted'];

  const kafkaCfg = cfg.get('events:kafka');
  for (let event of crudEvents) {
    kafkaCfg[`${collectionName}${event}`] = {
      protos: [
        `${pathPrefix}${collectionName}.proto`
      ],
      protoRoot: root,
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
  logger: any;
  server: chassis.Server;
  events: Events;
  commandInterface: AccessControlCommandInterface;
  accessController: core.AccessController;
  redisClient: RedisClient;
  authZ: ACSAuthZ;
  async start(cfg?: any, logger?: any): Promise<any> {
    this.cfg = cfg || await chassis.config.get();
    this.logger = logger || createLogger(this.cfg.get('logger'));

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

    // init Redis Client for subject index
    const redisConfig = this.cfg.get('redis');
    redisConfig.db = this.cfg.get('redis:db-indexes:db-subject');
    this.redisClient = createClient(redisConfig);

    const userTopic = events.topic(kafkaConfig.topics['user'].topic);
    // instantiate IDS client
    let userService;
    const grpcIDSConfig = this.cfg.get('client:user');
    if (grpcIDSConfig) {
      const idsClient = new Client(grpcIDSConfig, logger);
      userService = await idsClient.connect();
    }
    this.accessController = new core.AccessController(this.logger,
      this.cfg.get('policies:options'), userTopic, this.cfg, userService);

    // resources
    const db = await chassis.database.get(this.cfg.get('database:main'), this.logger);
    // init ACS cache
    initializeCache();
    // init AuthZ
    let authZ = await initAuthZ(this.cfg) as ACSAuthZ;
    this.authZ = authZ;
    const resourceManager = new ResourceManager(this.cfg, this.logger, events, db,
      this.accessController, this.redisClient, this.authZ);

    await server.bind('io-restorecommerce-policy-set-srv', resourceManager.getResourceService('policy_set'));
    // policy resource
    await server.bind('io-restorecommerce-policy-srv', resourceManager.getResourceService('policy'));
    // policy resource
    await server.bind('io-restorecommerce-rule-srv', resourceManager.getResourceService('rule'));
    // access control service
    const accessControlService = new AccessControlService(this.cfg, this.logger, resourceManager, this.accessController);
    await server.bind('io-restorecommerce-access-control-srv', accessControlService);
    // command interface
    this.commandInterface = new AccessControlCommandInterface(server, this.cfg,
      this.logger, events, accessControlService, this.redisClient);
    await server.bind('io-restorecommerce-access-control-ci', this.commandInterface);

    await server.bind('grpc-health-v1', new chassis.Health(this.commandInterface, {
      readiness: async () => !!await ((db as Arango).db).version()
    }));

    this.events = events;
    this.server = server;
    await server.start();

    this.logger.info('Access control service started correctly!');
    this.logger.info('Loading resources...');
    await accessControlService.loadPolicies();

    const that = this;
    const eventListener = async (msg: any,
      context: any, config: any, eventName: string): Promise<any> => {
      if (acsEvents.indexOf(eventName) > -1) {
        await accessControlService.loadPolicies();
      } else if (eventName === hierarchicalScopesResponse) {
        // Add subject_id to waiting list
        const hierarchical_scopes = msg.hierarchical_scopes;
        const tokenDate = msg.token;
        if (!_.isEmpty(hierarchical_scopes)) {
          // store HR scopes to cache with subjectID
          const subID = msg.subject_id;
          const token = tokenDate.split(':')[0];
          let redisHRScopesKey;
          let subject;
          if (token) {
            subject = await this.accessController.userService.findByToken({ token });
            if (subject && subject.data) {
              const tokens = subject.data.tokens;
              const subID = subject.data.id;
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
                  that.accessController.setRedisKey(redisSubKey, JSON.stringify(subject.data));
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
            for (let obj of updatedRoleAssocs) {
              roleAssocEqual = _.find(redisRoleAssocs, obj);
              if (!roleAssocEqual) {
                logger.debug('Subject Role assocation has been updated', obj);
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
                tokensEqual = _.find(redisTokens, token);
                if (!tokensEqual) {
                  logger.debug('Subject Token scope has been updated', token);
                  break;
                }
              } else {
                tokensEqual = true;
              }
            }
            if (!roleAssocEqual || !tokensEqual || (updatedRoleAssocs.length != redisRoleAssocs.length)) {
              logger.info('Evicting HR scope for Subject', { id: msg.id });
              await that.accessController.evictHRScopes(msg.id); // flush HR scopes
            }
          }
        }
      } else {
        await that.commandInterface.command(msg, context);
      }
    };

    for (let topicLabel in kafkaConfig.topics) {
      const topicCfg = kafkaConfig.topics[topicLabel];
      const topic = events.topic(topicCfg.topic);

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
