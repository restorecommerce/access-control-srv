import { ContextQuery } from '../interfaces';

export interface ResourceAdapter {
  query(contextQuery: ContextQuery, context: any): Promise<any[]>;
}

export interface QueryResult {
  errors?: any;
  details?: any[];
}
