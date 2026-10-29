import { DatabaseProvider } from "@restorecommerce/chassis-srv";
import { Topic } from "@restorecommerce/kafka-client";
import { Logger } from "@restorecommerce/logger";
import { OwnershipDomainListResponse, OwnershipDomainList, OwnershipDomainServiceImplementation, OwnershipDomainServiceClient } from "@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/ownership_domain.js";
import { AccessControlledServiceBase } from "@restorecommerce/resource-base-interface/lib/experimental/AccessControlledServiceBase.js";
import { ServiceConfig } from "@restorecommerce/service-config";
import { ReadRequest, Filter_Operation, DeepPartial, DeleteRequest, DeleteResponse, Filter_ValueType } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/resource_base.js';
import { AuthZAction, Operation, access_controlled_function } from "@restorecommerce/acs-client";
import { randomUUID } from 'node:crypto';



export class OwnershipDomainService extends AccessControlledServiceBase<OwnershipDomainListResponse, OwnershipDomainList> implements OwnershipDomainServiceImplementation {
  cfg: any;
  logger: any;
  constructor(logger: Logger, topic: Topic, db: DatabaseProvider, cfg: ServiceConfig) {
    super('ownership_domain', topic, db, cfg, logger, true, 'ownership_domains');
    this.cfg = cfg;
    this.logger = logger;
  }

  private static async ODMetaDataInjectorFactory(
    self: OwnershipDomainService,
    request: OwnershipDomainList,
    context: any,
  ): Promise<OwnershipDomainList> {
    const urns = self?.cfg?.get('authorization:urns');
    const ids = Array.from(new Set(
      request.items?.map(
        (item) => item.id
      ).filter(
        id => id
      ) ?? []
    ).values());
    const meta_map = ids.length ? await self.read({
      filters: [{
        filters: [{
          field: '_key',
          operation: Filter_Operation.in,
          value: JSON.stringify(ids),
          type: Filter_ValueType.ARRAY,
        }]
      }],
      limit: ids.length,
      subject: request.subject
    }, context).then(
      (response: OwnershipDomainListResponse) => new Map(response.items?.filter(
        item => item.payload
      )?.map(
        item => [item.payload.id, item.payload.meta]
      ))
    ) : undefined;

    request.items?.forEach((item) => {
      item.meta ??= meta_map?.get(item.id) ?? {};
      item.meta.modified ??= new Date();
      item.meta.modified_by ??= request.subject?.id;
      item.meta.owners ??= [
        request.subject?.scope ? {
          id: urns.ownerIndicatoryEntity,
          value: entities.organization,
          attributes: [{
            id: urns.ownerInstance,
            value: request.subject.scope
          }],
        } : undefined,
        request.subject?.id ? {
          id: urns.ownerIndicatoryEntity,
          value: entities.user,
          attributes: [{
            id: urns.ownerInstance,
            value: request.subject.id
          }],
        } : undefined,
      ].filter(Boolean);
      if (item.attributes?.length)
        item.meta.owners.push(...item.attributes)
      item.id ??= randomUUID().replace(/-/g, '');
    });
    return request;
  }


  @access_controlled_function({
    action: AuthZAction.CREATE,
    operation: Operation.isAllowed,
    meta: OwnershipDomainService.ODMetaDataInjectorFactory,
  })
  override async create(request: OwnershipDomainList, ctx: any): Promise<DeepPartial<OwnershipDomainListResponse>> {
    return await super.create(request, ctx);
  }

  async read(request: ReadRequest, ctx: any): Promise<DeepPartial<OwnershipDomainListResponse>> {
    return await super.read(request, ctx);
  }

   @access_controlled_function({
    action: AuthZAction.DELETE,
    operation: Operation.isAllowed,
    meta: OwnershipDomainService.ODMetaDataInjectorFactory,
  })
  async delete(request: DeleteRequest, ctx: any): Promise<DeepPartial<DeleteResponse>> {
    return await super.delete(request, ctx);
  }

   @access_controlled_function({
    action: AuthZAction.MODIFY,
    operation: Operation.isAllowed,
    meta: OwnershipDomainService.ODMetaDataInjectorFactory,
  })
  async upsert(request: OwnershipDomainList, ctx: any): Promise<DeepPartial<OwnershipDomainListResponse>> {
    return await super.upsert(request, ctx);
  }
}