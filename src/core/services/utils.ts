import { Policy } from "@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/policy.js";
import { Rule } from "@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/rule.js";
import { FilterOperation } from "@restorecommerce/resource-base-interface";
import _ from "lodash";

export const marshallResource = (resource: any, resourceName: string): any => {
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

export const makeFilter = (ids: string[]): any => {
  return [{
    filters: [{
      field: 'id',
      operation: FilterOperation.in,
      value: ids
    }]
  }];
};