import { Effect, Rule } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/rule';
import { Policy } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/policy';
import { PolicySet } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/policy_set';
import { Attribute } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/attribute';
import { RoleAssociation as RoleAssociations, HierarchicalScope, Tokens } from '@restorecommerce/rc-grpc-clients/dist/generated-server/io/restorecommerce/auth';

export interface PolicyWithCombinables extends Policy {
  combinables: Map<string, Rule>;
}

export interface PolicySetWithCombinables extends PolicySet {
  combinables: Map<string, PolicyWithCombinables>;
}

export interface EffectEvaluation {
  effect: Effect;
  evaluation_cacheable: boolean;
}

export interface Obligation {
  obligation?: Attribute[];
}

export interface ContextWithSubResolved {
  subject: ContextSubjectResolved;
  resources: Resource[];
  security?: any; // session tokens, etc.
}

export interface ContextSubjectResolved {
  id?: string;
  role_associations?: RoleAssociations[];
  hierarchical_scopes?: HierarchicalScope[];
  token?: string;
  tokens?: Tokens[];
}

export interface Resource {
  id: string;
  meta: ResourceMeta;
  [key: string]: any;
}

export interface ResourceMeta {
  created: Date;
  modified: Date;
  acls?: Attribute[];
  owners: Attribute[];
}

export interface CombiningAlgorithm {
  urn: string;
  method: string;
}

export interface AccessControlConfiguration {
  combiningAlgorithms?: CombiningAlgorithm[];
  urns?: { [key: string]: string };
}

export type AccessControlOperation = 'whatIsAllowed' | 'isAllowed';
