export interface AccessControlObjectInterface {
  id?: string;
  name?: string;
  description?: string;
  target?: Target;
  effect?: Effect;
}

export interface Combinable extends AccessControlObjectInterface { }
export interface Rule extends Combinable {
  effect: Effect; // effect is never optional in rule
  contextQuery?: ContextQuery;
  condition?: any;
}

export interface Combiner<T extends Combinable> extends AccessControlObjectInterface {
  combinables: Map<string, T>;  // combinables mapped by their IDs
  combiningAlgorithm: string;
}

export interface Policy extends Combiner<Rule>, Combinable { }
export interface PolicySet extends Combiner<Policy> { }

export interface Attribute {
  id: string;
  value: string;
}

export interface Target {
  // each map is an attribute with (key, value) pairs
  subject: Attribute[];
  resources: Attribute[];
  action: Attribute[];
}

export interface ContextQuery {
  filters: GQLFilter[];
  query: string;
}

export enum Effect {
  PERMIT = "PERMIT",
  DENY = "DENY"
}

export enum Decision {
  PERMIT = "PERMIT",
  DENY = "DENY",
  INDETERMINATE = "INDETERMINATE"
}

export interface Request {
  target: Target;
  context: Context; //  data for context query and evaluated code
}

export interface Context {
  subject: ContextSubject;
  resources: Resource[];
  security?: any; // session tokens, etc.
}

export interface ContextSubject {
  id: string;
  role_associations: RoleAssociations[];
  hierarchical_scope?: HierarchicalScope[];
}

export interface RoleAssociations {
  role: string;
  attributes: Attribute[];
}

export interface HierarchicalScope {
  id: string;
  children?: HierarchicalScope[];
}

export interface Resource {
  id: string;
  meta: ResourceMeta;
  [key: string]: any;
}

export interface ResourceMeta {
  created: number;
  modified: number;
  owner: ResourceOwnerAttributes[];
}

export interface ResourceOwnerAttributes {
  id: string;
  value: string;
}

export interface Response {
  decision: Decision;
  obligation: string;
}

export interface CombiningAlgorithm {
  urn: string;
  method: string;
}

export interface AccessControlConfiguration {
  combiningAlgorithms?: CombiningAlgorithm[];
  urns?: { [key: string]: string };
}

export interface GQLFilter {
  field: string;
  operation: string;
  value: string;
}

// Reverse query response
export interface PolicySetRQ extends AccessControlObjectInterface {
  combining_algorithm: string;
  policies?: PolicyRQ[];
}

export interface PolicyRQ extends AccessControlObjectInterface {
  rules?: RuleRQ[];
  has_rules?: boolean;
  combining_algorithm?: string;
}

export interface RuleRQ extends AccessControlObjectInterface { }

export type AccessControlOperation = 'whatIsAllowed' | 'isAllowed';
