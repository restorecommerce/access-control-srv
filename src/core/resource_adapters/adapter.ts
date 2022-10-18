import { ContextQuery } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/rule';

export interface ResourceAdapter {
  query(contextQuery: ContextQuery, context: any): Promise<any[]>;
}

export interface QueryResult {
  operation_status?: {
    code?: number;
    message?: string;
  };
  details?: any[];
}
