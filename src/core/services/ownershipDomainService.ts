import { DatabaseProvider } from "@restorecommerce/chassis-srv";
import { Topic } from "@restorecommerce/kafka-client";
import { Logger } from "@restorecommerce/logger";
import {
  OwnershipDomainListResponse,
  OwnershipDomainList,
  OwnershipDomainServiceImplementation
} from "@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/ownership_domain.js";
import { AccessControlledServiceBase } from "@restorecommerce/resource-base-interface/lib/experimental/AccessControlledServiceBase.js";
import { ServiceConfig } from "@restorecommerce/service-config";
import { CallContext } from "@restorecommerce/grpc-client";
import {
  Filter_Operation,
  DeepPartial,
  DeleteRequest,
  DeleteResponse,
  Filter_ValueType,
} from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/resource_base.js';
import {
  AuthZAction,
  Operation,
  access_controlled_function,
  urns,
  entities,
} from "@restorecommerce/acs-client";
import { randomUUID } from 'node:crypto';
import * as _ from 'lodash-es';

const URNS = {
  ...entities,
  ...urns,
};

async function ODMetaDataInjector(
  self: OwnershipDomainService,
  request: OwnershipDomainList,
  context: CallContext,
): Promise<OwnershipDomainList> {
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
        id: URNS.ownerIndicatoryEntity,
        value: URNS.organization,
        attributes: [{
          id: URNS.ownerInstance,
          value: request.subject.scope
        }],
      } : undefined,
      request.subject?.id ? {
        id: URNS.ownerIndicatoryEntity,
        value: URNS.user,
        attributes: [{
          id: URNS.ownerInstance,
          value: request.subject.id
        }],
      } : undefined,
    ].filter(Boolean);
    item.meta.owners.push(...(item.attributes?.filter(
      a => a.id === urns.ownerIndicatoryEntity
        && item.meta.owners?.every(
          o => !_.isEqual(o, a) // not deep equal
        )
    ) ?? []));
    item.meta.acls.push(...(item.attributes?.filter(
      a => a.id === urns.aclIndicatoryEntity
        && item.meta.acls?.every(
          o => !_.isEqual(o, a)
        )
    ) ?? []));
    item.id ??= randomUUID().replace(/-/g, '');
  });
  return request;
}

export class OwnershipDomainService
  extends AccessControlledServiceBase<OwnershipDomainListResponse, OwnershipDomainList>
  implements OwnershipDomainServiceImplementation
{
  constructor(
    logger: Logger,
    topic: Topic,
    db: DatabaseProvider,
    public readonly cfg: ServiceConfig,
  ) {
    super('ownership_domain', topic, db, cfg, logger, true, 'ownership_domains');
  }

  @access_controlled_function({
    action: AuthZAction.CREATE,
    operation: Operation.isAllowed,
    meta: ODMetaDataInjector,
  })
  override async create(request: OwnershipDomainList, ctx: CallContext): Promise<DeepPartial<OwnershipDomainListResponse>> {
    return await super.create(request, ctx);
  }

   @access_controlled_function({
    action: AuthZAction.DELETE,
    operation: Operation.isAllowed,
    meta: ODMetaDataInjector,
  })
  override async delete(request: DeleteRequest, ctx: CallContext): Promise<DeepPartial<DeleteResponse>> {
    return await super.delete(request, ctx);
  }

  @access_controlled_function({
    action: AuthZAction.MODIFY,
    operation: Operation.isAllowed,
    meta: ODMetaDataInjector,
  })
  override async upsert(request: OwnershipDomainList, ctx: CallContext): Promise<DeepPartial<OwnershipDomainListResponse>> {
    return await super.upsert(request, ctx);
  }

  @access_controlled_function({
    action: AuthZAction.MODIFY,
    operation: Operation.isAllowed,
    meta: ODMetaDataInjector,
  })
  override async update(request: OwnershipDomainList, ctx: CallContext): Promise<DeepPartial<OwnershipDomainListResponse>> {
    return await super.update(request, ctx);
  }
}