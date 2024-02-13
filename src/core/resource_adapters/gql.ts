import { ResourceAdapter, QueryResult } from './adapter.js';
import pkg from 'apollo-client';
import gql from 'graphql-tag';
import { InMemoryCache } from 'apollo-cache-inmemory';
import { HttpLink } from 'apollo-link-http';
import * as _ from 'lodash-es';
import { ContextQuery } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/rule.js';
import { Request } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/access_control.js';
import * as errors from '../errors.js';
import fetch from 'cross-fetch';

const { ApolloClient } = pkg;

export class GraphQLAdapter implements ResourceAdapter {
  constructor(private url: string, private logger: any, private clientOpts: any = {}) {
    if (_.isEmpty(url) || _.isNil(url)) {
      throw new Error('Missing resource adapter URL');
    }
  }

  /**
   * GraphQL query. This implementation always expects a response
   * @param contextQuery A Rule's `context_query` object.
   * @param context The Request's contextual data.
   */
  async query(contextQuery: ContextQuery, request: Request): Promise<any[]> {
    const filters = _.cloneDeep(contextQuery.filters);
    const resources = request?.target?.resources ? request.target.resources : [];
    let queryFilters = [];
    for (let filtersObj of filters) {
      for (let filter of filtersObj.filters) {
        // search for property in resources
        if (!filter.value.match(/urn:*#*/)) {
          throw new Error('Invalid property name specified for resource adapter filter');
        }
        const split = filter.value.split('#');
        const entity = split[0];
        const property = split[1];

        let match = false;
        for (let resourceAttribute of resources) {
          if (resourceAttribute.id == 'urn:restorecommerce:acs:names:model:entity' && resourceAttribute.value == entity) {
            match = true;
          } else if (resourceAttribute.id == 'urn:oasis:names:tc:xacml:1.0:resource:resource-id' && match) {
            const resourceID = resourceAttribute.value;
            // when request is recived in accessControlService request.context is unmarshalled with unmarshallContext()
            const resource = _.find((request.context as any).resources ?? [], r => r.id == resourceID);
            filter.value = _.get(resource, property);

            queryFilters.push(filter);
            match = false;
          }
        }
      }
    }

    let filtersArr = [];
    if (_.isEmpty(queryFilters)) {
      this.logger.warn('No filter provided for GQL adapter query; skipping');
      return null;
    } else {
      filtersArr = [{ filter: queryFilters }];
    }

    const query = contextQuery.query;
    const securityCtx = request.context.security || {}; // cookies / session tokens / other related security attributes
    const headers = _.assign({}, this.clientOpts.headers, { 'Content-Type': 'application/json' }, securityCtx);
    let client;
    try {
      client = new ApolloClient({
        link: new HttpLink({ uri: this.url, fetch, headers }),
        cache: new InMemoryCache({ addTypename: false })
      });
    } catch (err) {
      throw new Error('Error occured creating graphql client');
    }
    const response = await client.query({ query: gql`${query}`, variables: { filters: filtersArr } });
    if (_.isEmpty(response)) {
      throw new errors.UnexpectedContextQueryResponse('Empty response');
    }

    const queryName = _.keys(response.data)[0];
    const result: QueryResult = response.data[queryName];
    if (result?.operation_status?.code && result.operation_status.code != 200) {
      this.logger.error('Context query result contains errors', result.operation_status);
      throw new errors.UnexpectedContextQueryResponse(result.operation_status.message);
    }

    return result.details || [];
  }
}
