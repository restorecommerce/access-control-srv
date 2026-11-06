import { DatabaseProvider } from "@restorecommerce/chassis-srv";
import { CallContext } from "@restorecommerce/grpc-client";
import { Topic } from "@restorecommerce/kafka-client";
import { DeepPartial } from "@restorecommerce/kafka-client/dist/protos.js";
import { Logger } from "@restorecommerce/logger";
import { ResourceListResponse, DeleteRequest, DeleteResponse } from "@restorecommerce/rc-grpc-clients/dist/generated/io/restorecommerce/resource_base.js";
import { ElementOf, ResourceList } from "@restorecommerce/resource-base-interface";
import { AccessControlledServiceBase } from "@restorecommerce/resource-base-interface/lib/experimental/AccessControlledServiceBase.js";
import { ServiceConfig } from "@restorecommerce/service-config";



export interface CacheSync<T> {
  onWrite(items: T[]): void | Promise<void>;
  onDelete(ids: string[], dropAll: boolean): void;
}

export abstract class CacheSyncedResourceService<
  I extends ResourceList,
  O extends ResourceListResponse
> extends AccessControlledServiceBase<O, I> {

  protected constructor(
    resourceName: string,
    topic: Topic,
    db: DatabaseProvider,
    cfg: ServiceConfig,
    logger: Logger,
    enableEvents: boolean,
    collectionName: string,
    protected readonly cacheSync?: CacheSync<ElementOf<I['items']>>,
  ) {
    super(resourceName, topic, db, cfg, logger, enableEvents, collectionName);
  }

  protected abstract marshall(payload: any): ElementOf<I['items']>;

  private async syncWrite(result: DeepPartial<O>): Promise<DeepPartial<O>> {
    const items = (result as any)?.items?.filter((i: any) => i.payload);
    if (items?.length) {
      await this.cacheSync?.onWrite(items.map((i: any) => this.marshall(i.payload)));
    }
    return result;
  }
  
  protected async superCreate(request: I, context?: CallContext): Promise<DeepPartial<O>> {
    return this.syncWrite(await super.superCreate(request, context));
  }

  protected async superUpdate(request: I, context?: CallContext): Promise<DeepPartial<O>> {
    return this.syncWrite(await super.superUpdate(request, context));
  }

  protected async superUpsert(request: I, context?: CallContext): Promise<DeepPartial<O>> {
    return this.syncWrite(await super.superUpsert(request, context));
  }

  protected async superDelete(request: DeleteRequest, context?: CallContext): Promise<DeleteResponse> {
    const result = await super.superDelete(request, context);
    this.cacheSync?.onDelete(request.ids ?? [], !!request.collection);
    return result;
  }
}