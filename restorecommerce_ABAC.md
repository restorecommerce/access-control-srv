# ABAC Core for Restorecommerce

[Attribute based access control][ABAC] with for Restorecommerce
inspired by [XACML](http://en.wikipedia.org/wiki/XACML).

[ABAC]: http://en.wikipedia.org/wiki/Attribute_Based_Access_Control

## Data Model / Message Structure

### `Policy`

A Policy consisting of rules.

```yml
- name
- description
- combiningAlgorithm [urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides | urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:permit-overrides | ]
(- target)
- rule                    Reference to 1..n rules
- effect [permit, deny]
```

### `PolicySet`

A set of policies.

```yml
- name
- description
- combiningAlgorithm      See policy
- policy                  Reference to 1..n policies
```

### `Rule`

Atomic element of the ABAC system.

```yml
- name
- description
- contextQuery            GraphQL Queries whose results are provided in the data context of the evaluated code to provide essential information for the decision making
- target
  - resource
    - attribute
      - id                ex: urn:restorecommerce:acs:names:model:entity
      - value             ex: urn:restorecommerce:acs:model:devices.Device
  - action
    - attribute
      - id
      - value
- condition               JavaScript Code, ex: subject.roles.includes('admin')
- effect [permit, deny]
```

### General

The `subject`, `resource`, `action` properties are arrays and can contain 1..n elements.

## API (Core Interface)

There are two main operations exposed through the API:

```ts
isAllowed(request: Request): Response
```

This method is used to evaluate a request based on the active policies.

```ts
whatIsAllowed(request: Request): PolicySetList
```

This method returns a set of policies which match the request's target for client-side evaluation.
It is useful for cases in which there is not a specific target resource for a request like, for example,
when a user aims to see as much resources as possible; in a such case, it is possible to call `whatIsAllowed` in order to infer on the
client side how the resources would be filtered.

*Note*: this feature does not return any rule based on policy evaluation through dynamic code execution (through the `condition` property)
as demanding such evaluation  would require a replication of this functionality at client-side.

### `Request`

```yml
- subject
  - attribute
    - id         ex: urn:restorecommerce:acs:names:model:entity
    - value      ex: User
    - id         ex: urn:oasis:names:tc:xacml:1.0:subject:subject-id
    - value      ex: alice
- resource
  - attribute
    # To identify a domain model type
    - id         ex: urn:restorecommerce:acs:names:model:entity
    - value      ex: urn:restorecommerce:acs:model:user.User

    # To identify a single resource by its unique ID
    - id         ex: urn:oasis:names:tc:xacml:1.0:resource:resource-id
    - value      ex: <some UUID>

    # To identify a property of the selected resource(s)
    - id         ex: urn:restorecommerce:acs:names:model:property
    - value      ex: urn:xingular:model:User#password
- action
  - attribute
    - id         ex: urn:oasis:names:tc:xacml:1.0:action:action-id
    - value      ex: urn:restorecommerce:acs:names:action:modify
- context
```

### `Response`

```yml
- decision [PERMIT, DENY, NOT-APPLICABLE, INDETERMINATE]
- obligation              TBD
```

## URN Reference

### Restorecommerce defined

- `urn:restorecommerce:acs:*`                                 ACS Related
- `urn:restorecommerce:acs:model:*`                           Domain model related
- `urn:restorecommerce:acs:names:*`                           Keywords for access control related concepts
- `urn:restorecommerce:acs:names:role`                        Role as in RBAC
- `urn:restorecommerce:acs:names:roleScopingEntity`           Scopes a role by a given type
- `urn:restorecommerce:acs:names:roleScopeInstance`           Specify an actual instance of a scoping entity by its ID
- `urn:restorecommerce:acs:names:ownerIndicatoryEntity`       Specify the entity which indicates the owner of a resource
- `urn:restorecommerce:acs:names:ownerInstance`               Specify an actual instance of an owner entity
- `urn:restorecommerce:acs:names:model:entity`                An entity (type)
- `urn:restorecommerce:acs:names:model:property`              A property of an entity
- `urn:restorecommerce:acs:names:operation`                   An operation (e. g. a mutation or query in a GraphQL API or a gRPC method)
- `urn:restorecommerce:acs:names:action:read`                 Read access
- `urn:restorecommerce:acs:names:action:modify`               Modify (update) access
- `urn:restorecommerce:acs:names:action:create`               Create access
- `urn:restorecommerce:acs:names:action:delete`               Delete access
- `urn:restorecommerce:acs:names:action:execute`              Execute access

### XACML

- `urn:oasis:names:tc:xacml:1.0:resource:resource-id`         An resource ID which can uniquely identify an instance of a given entity type
- `urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm`     Diverse rule combining algorithms
- `urn:oasis:names:tc:xacml:1.0:action:action-id`             Denotes an action ID that in-turn defines an action performed on the given resource

# Concepts

## Role Scoping

A role might be scoped with a scoping entity which introduces a scope as third dimension to the typical RBAC tupel of user and role.
This is an important concept for multi-tenancy whereas the scope can be perceived as a tenant. As an example take a multi-national corporation with
lots of branches and business units and these business units need to be isolated from each other in terms of data visibility.
As the entity might be modeled to foresee a hierarchical relationship via a `parent` property, hierarchy aware isolation is possible.

# Examples

# Resource based and involving hierarchical Scope Evaluation

A user whose ID is 'Alice' has the role 'admin' within the scoping entity `Organization` with ID 'OrgA'.
This user aims to 'read' a resource of type `Device`. The device is owned by an `Organization` with ID 'OrgA'.

Request:

```yml
request:
    target:
        subject:
           - id: urn:oasis:names:tc:xacml:1.0:resource:resource-id
             value: Alice
           - id: urn:restorecommerce:acs:names:role
             value: admin
           - id: urn:restorecommerce:acs:names:roleScopingEntity
             value: urn:restorecommerce:acs:model:organization.Organization
           - id: urn:restorecommerce:acs:names:roleScopeInstance
             value: OrgA
        resources:
           - id: urn:restorecommerce:acs:names:model:entity
             value: urn:restorecommerce:acs:model:device.Device
           - id: urn:oasis:names:tc:xacml:1.0:resource:resource-id
             value: deviceX
        action:
           - id: urn:oasis:names:tc:xacml:1.0:action:action-id
             value: urn:restorecommerce:acs:names:action:read
    context:
        subject:
            id: Alice
            name: Alice
            role_associations:
                - role: admin
                  attributes: # a list of attributes associated with the role
                   - id: urn:restorecommerce:acs:names:roleScopingEntity
                     value: urn:restorecommerce:acs:model:organization.Organization
                   - id: urn:restorecommerce:acs:names:roleScopeInstance
                     value: OrgA
            hierarchical_scope: # sub-tree of the scoping entity
              - id: orgA
                children:
                  - id: orgB
        resources:
            - id: deviceX
              name: Device X
              description: A simple device
              meta:
               created: <timestamp>
               modified: <timestamp>
               modified_by: RandomUser
               owner:
                 - id: urn:restorecommerce:acs:names:ownerIndicatoryEntity
                   value: urn:restorecommerce:acs:model:organization.Organization
                 - id: urn:restorecommerce:acs:names:ownerInstance
                   value: OrgB
                 - id: urn:restorecommerce:acs:names:ownerIndicatoryEntity
                   value: urn:restorecommerce:acs:model:user.User
                 - id: urn:restorecommerce:acs:names:ownerInstance
                   value: RandomUser
```

Policies:

```yml
policy_sets:
 - name: PolicySet A
   description: General policy set.
   combining_algorithm: urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:permit-overrides
   policies:
    - name: Policy A
      description: A policy which contains device-related rules
      combining_algorithm: urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:permit-overrides
      rules:
        - name: Rule A
          description: A simple rule targeting a `read` by `Organization`-scoped users on Devices
          target:
            resources:
                - id: urn:restorecommerce:acs:names:model:entity
                  value: urn:restorecommerce:acs:model:device.Device
            action:
                - id: urn:oasis:names:tc:xacml:1.0:action:action-id
                  value: urn:restorecommerce:acs:names:action:read
            subject:
                - id: urn:restorecommerce:acs:names:role
                  value: admin
                - id: urn:restorecommerce:acs:names:roleScopingEntity
                  value: urn:restorecommerce:acs:model:organization.Organization
          effect: PERMIT
```

As a precondition, the targeted resources should be owned by a hierarchical resource among the user's role scoping entities.
All relevant information under the `subject` and `resources` property are passed within the context.
If one of the device's owner attributes exists within the subject's role scoping entities,
the request's target is then matched against the existing rules. Otherwise, the access is denied.

In the given example, the targeted resource's owner has among its attributes an `Organization` with ID `OrgA`,
which is passed in the subject's contextual information with organization 'OrgB' as its children.
Since the device is owned by `OrgB`, it is considered to be under the subject's hierarchical scope and therefore the matching rules can be checked.

There is one policy with one rule, which permits access by `Organization`-scoped users with role `admin` to resources of entity `Device`.
Since the request's target matches all attributes from this rule a `PERMIT` effect is returned,
which according to the policy's combining algorithm means access should be granted to the resource.

## Just Operation based

Policies:

```yml
...
      rules:
        - name: Rule A
          description: A simple rule targeting a high level operation in the GraphQL API
          target:
            resources:
                - id: urn:restorecommerce:acs:names:operation
                  value: mutation.orgDelete
            action:
                - id: urn:oasis:names:tc:xacml:1.0:action:action-id
                  value: urn:restorecommerce:acs:names:action:execute
            subject:
                - id: urn:restorecommerce:acs:names:role
                  value: admin
                - id: urn:restorecommerce:acs:names:roleScopingEntity
                  value: urn:restorecommerce:acs:model:organization.Organization
          effect: PERMIT
```

# Architecture Decisions

- No internal attribute store such as Predix ACS.
- Adapters to pull resource or subject attributes for example via GQL.

# Future Stuff

## Further Attributes describing a Subject

- type [systemuser|]

## Further potential Attributes describing a Request (Environment)

- `geoLocation`
- `connection`
  - `remoteIpv4Address`
  - `callRate`
