import { ResourceAdapter, QueryResult } from './adapter';
import { ApolloClient } from 'apollo-client';
import gql from 'graphql-tag';
import { InMemoryCache } from 'apollo-cache-inmemory';
import { HttpLink } from 'apollo-link-http';
import * as _ from 'lodash';
import { ContextQuery, Request } from '../interfaces';
import * as errors from '../errors';
import fetch from 'cross-fetch';

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
    const resources = request.target.resources;
    const queryFilters = [];
    for (let filter of filters) {
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
          const resource = _.find(request.context.resources, r => r.id == resourceID);
          filter.value = _.get(resource, property);

          queryFilters.push(filter);
          match = false;
        }
      }
    }

    if (_.isEmpty(queryFilters)) {
      this.logger.warn('No filter provided for GQL adapter query; skipping');
      return null;
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
    const response = await client.query({ query: gql`${query}`, variables: { filter: queryFilters } });
    if (_.isEmpty(response)) {
      throw new errors.UnexpectedContextQueryResponse('Empty response');
    }

    const queryName = _.keys(response.data)[0];
    const result: QueryResult = response.data[queryName];
    if (!_.isEmpty(result.errors)) {
      this.logger.error('Context query result contains errors:', { errors: result.errors });
      throw new errors.UnexpectedContextQueryResponse(result.errors);
    }

    return result.details || [];
  }
}
