import { DatabaseProvider } from "@restorecommerce/chassis-srv";
import { Topic } from "@restorecommerce/kafka-client";
import { Logger } from "@restorecommerce/logger";
import { OwnershipDomainListResponse, OwnershipDomainList, OwnershipDomainServiceImplementation } from "@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/ownership_domain.js";
import { AccessControlledServiceBase } from "@restorecommerce/resource-base-interface/lib/experimental/AccessControlledServiceBase.js";
import { ServiceConfig } from "@restorecommerce/service-config";


export class OwnershipDomainService extends AccessControlledServiceBase<OwnershipDomainListResponse, OwnershipDomainList> implements OwnershipDomainServiceImplementation {
  constructor(logger: Logger, topic: Topic, db: DatabaseProvider, cfg: ServiceConfig) {
    super('ownership_domain', topic, db, cfg, logger, true, 'ownership_domains');
  }
}