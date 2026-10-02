import { DatabaseProvider } from "@restorecommerce/chassis-srv";
import { Topic } from "@restorecommerce/kafka-client";
import { DeepPartial } from "@restorecommerce/kafka-client/dist/protos.js";
import { Logger } from "@restorecommerce/logger";
import { Filter_Operation } from "@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/graph.js";
import { Rule, RuleList, RuleListResponse, RuleServiceImplementation } from "@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/rule.js";
import { ReadRequest } from "@restorecommerce/resource-base-interface";
import { ServiceConfig } from "@restorecommerce/service-config";
import { CacheSyncedResourceService } from "./cacheSyncedResourceService.js";
import { makeFilter, marshallResource } from "./utils.js";
import { AccessController } from '../accessController.js';


export class RuleService extends CacheSyncedResourceService<Rule, RuleList, RuleListResponse> implements RuleServiceImplementation {
  constructor(logger: Logger, topic: Topic, db: DatabaseProvider, cfg: ServiceConfig, _accessController: AccessController) {
    super('rule', topic, db, cfg, logger, true, 'rules', {
      onWrite: (rules) => {
        for (const rule of rules) {
          for (const [, policySet] of _accessController.policySets) {
            for (const [, policy] of policySet.combinables) {
              if (policy?.combinables?.has(rule.id)) {
                _accessController.updateRule(policySet.id, policy.id, rule);
              }
            }
          }
        }
      },
      onDelete: (ids, dropAll) => {
        if (dropAll) {
          for (const [, policySet] of _accessController.policySets) {
            for (const [, policy] of policySet.combinables) {
              policy.combinables = new Map();
              _accessController.updatePolicy(policySet.id, policy);
            }
          }
          return;
        }
        for (const id of ids) {
          for (const [, policySet] of _accessController.policySets) {
            for (const [, policy] of policySet.combinables) {
              if (policy?.combinables?.has(id)) {
                _accessController.removeRule(policySet.id, policy.id, id);
              }
            }
          }
        }
      },
    });
  }

  protected marshall(payload: any): Rule {
    return marshallResource(payload, 'rule');
  }

  // subjektloser Systemzugriff – ACS-Bypass über superRead
  async load(): Promise<Map<string, Rule>> {
    return this.getRules();
  }

  async getRules(ruleIDs?: string[]): Promise<Map<string, Rule>> {
    const filters = ruleIDs ? makeFilter(ruleIDs) : {};
    const result = await this.superRead(ReadRequest.fromPartial({ filters }));
    const rules = new Map<string, Rule>();
    for (const item of result?.items ?? []) {
      if (item?.payload?.id) rules.set(item.payload.id, this.marshall(item.payload));
    }
    return rules;
  }

  async readMetaData(id?: string): Promise<DeepPartial<RuleListResponse>> {
    return this.superRead(ReadRequest.fromPartial({
      filters: [{ filters: [{ field: 'id', operation: Filter_Operation.eq, value: id }] }]
    }));
  }
}