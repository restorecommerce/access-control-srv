# access-control-srv

[![Build Status][build]](https://travis-ci.org/restorecommerce/access-control-srv?branch=master)[![Dependencies][depend]](https://david-dm.org/restorecommerce/access-control-srv)[![Coverage Status][cover]](https://coveralls.io/github/restorecommerce/access-control-srv?branch=master)

[build]: http://img.shields.io/travis/restorecommerce/access-control-srv/master.svg?style=flat-square
[depend]: https://img.shields.io/david/restorecommerce/access-control-srv.svg?style=flat-square
[cover]: http://img.shields.io/coveralls/restorecommerce/access-control-srv/master.svg?style=flat-square

Features:

- [Attribute-based access control](https://en.wikipedia.org/wiki/Attribute-based_access_control) inspired by [XACML](https://en.wikipedia.org/wiki/XACML)
- Implementing the PAP (partially), PDP, PRP
- Supports arbitrary policies based on arbitrary attributes such as scoped roles as supported by the [Identity Service](https://github.com/restorecommerce/identity-srv)
- Control access to distributed resources centrally using [Rule, Policy and PolicySet](https://github.com/restorecommerce/access-control-srv/blob/master/restorecommerce_ABAC.md#data-model-message-structure)
- exposes a [gRPC](https://grpc.io/docs/) interface for handling CRUD operations and access-control specific functionalities
- Authorization policies can be updated at run time and affect all clients immediately

The microservice manages access-control-specific resources `Rule`, `Policy` and `PolicySet` exposed though [Resource Manager](resourceManager.ts) service which extend the [resource-base-interface](https://github.com/restorecommerce/resource-base-interface) generic class ServiceBase. This service persists resources `Rule`, `Policy` and `PolicySet` within an [ArangoDB](https://www.arangodb.com/) instance and message interfaces defined with [Protocol Buffers](https://developers.google.com/protocol-buffers/). These resources can be loaded from local YAML files and/or handled generically through [gRPC](https://grpc.io/docs/) CRUD operations. A [detailed description](restorecommerce_ABAC.md) describes how ABAC is implemented and URN references for `subject`, `resources` and `action` attributes.

## Configuration

A GraphQL adapter has been integrated into the service for executing context queries [`io.restorecommerce.rule.ContextQuery`](https://github.com/restorecommerce/access-control-srv/tree/dev#rule) to obtain required information to make the access decision. This GraphQL endpoint can be configured using `adapter.graphql.url` property in the [configuration](cfg/config.json).

## gRPC Interface

This microservice exposes the following gRPC endpoints:

### Rule

A Rule resource.

`io.restorecommerce.rule.Rule`

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | string | required | Rule ID. |
| name | string | optional | Rule name. |
| description | string | optional | Rule description. |
| target | `io.restorecommerce.access_control.Target` | optional | Rule target. |
| context_query | `io.restorecommerce.rule.ContextQuery` | optional | GraphQL query which can be performed to obtain required info for request. |
| condition | string | optional | Custom Javascript code to check if rule is applicable. |
| effect | `io.restorecommerce.access_control.Effect` | required | Rule effect; possible values are `PERMIT` and `DENY` |

`io.restorecommerce.access_control.Target`

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| subject | [ ]`io.restorecommerce.access_control.Property` | required | Entity requesting access. |
| resources | [ ]`io.restorecommerce.access_control.Property` | required | Resources to be accessed. |
| action | [ ]`io.restorecommerce.access_control.Property` | required | Action to be performed on resources |

`io.restorecommerce.access_control.Property`

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | string | required | Attribute ID |
| value | string | required | Attribute value |

`io.restorecommerce.rule.ContextQuery`

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| query | string | required | Query to retrieve external resources. |
| filters | [ ]`io.restorecommerce.rule.Filter` | optional | List of argument keys to be passed from `Request#context` to `query`. |

`io.restorecommerce.rule.Filter`

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| field | string | optional | field to query |
| operation | string | optional | operation |
| value | string | optional | value |

### Policy

A Policy resource consisting of set of Rules.

`io.restorecommerce.policy.Policy`

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | string | required | Policy ID. |
| name | string | optional | Policy name. |
| description | string | optional | Policy description. |
| target | `io.restorecommerce.access_control.Target` | optional | Policy target. |
| rules | [ ] `io.restorecommerce.rule.Rule` | optional | List of rules binded to a policy. |
| combining_algorithm | string | optional | Combining algorithm to be applied to the rules set. |

### PolicySet

A PolicySet resource consisting of set of Policies.

`io.restorecommerce.policy_set.PolicySet`

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | string | required | Policy ID. |
| name | string | optional | Policy name. |
| description | string | optional | Policy description. |
| target | `io.restorecommerce.access_control.Target` | optional | Policy target. |
| policies | [ ] `io.restorecommerce.policy.Policy` | required | List of policies binded to a policy set. |
| combining_algorithm | string | optional | Combining algorithm to be applied to the policy set. |

#### `IsAllowed`

This operation is used when the target resource is known and it decides the outcome of an access control request. The policy or policy set is found to apply to a given request, its rules are evaluated to determine the access decision and response. Requests are performed providing `io.restorecommerce.access_control.Request` protobuf message as input and responses are a `io.restorecommerce.access_control.Response` message.

`io.restorecommerce.access_control.Request`

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| target | `io.restorecommerce.access_control.Target` | required | Request target. |
| context | `google.protobuf.Any` | required | Context variables for access control decisions based on custom scripts |

`io.restorecommerce.access_control.Response`

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| decision | `io.restorecommerce.access_control.Decision` | required | Access decision; possible values are `PERMIT`, `DENY` and `INDETERMINATE` |
| obligation | string | optional | Obligation attached to decision |

#### `WhatIsAllowed`

This operation is used when there is not a specific target resource for a request. It returns a reverse query containing only the policies and rules applicable to a given request. They can then be used on the client side to infer permissions. Requests are performed providing `io.restorecommerce.access_control.Request` protobuf message as input and responses are a `io.restorecommerce.access_control.ReverseQuery` message.

`io.restorecommerce.access_control.Request`

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| target | `io.restorecommerce.access_control.Target` | required | Request target. |
| context | `google.protobuf.Any` | required | Context variables for access control decisions based on custom scripts |

`io.restorecommerce.access_control.ReverseQuery`

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| policy_sets | `io.restorecommerce.policy_set.PolicySetRQ` | required | List of applicable policy sets |

`io.restorecommerce.policy_set.PolicySetRQ`

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | string | required | Policy Set ID |
| target | `io.restorecommerce.access_control.Target` | optional | Policy set target |
| combining_algoritm | string | optional | Combining algorithm. |
| effect | `io.restorecommerce.access_control.Effect` | optional | A policy target's effect (only applicable if there are no rules). |
| policies | `io.restorecommerce.policy.PolicyRQ` | optional | List of policies bound to a policy set |

`io.restorecommerce.policy.PolicyRQ`

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | string | required | Policy ID |
| target | `io.restorecommerce.access_control.Target` | optional | Policy target |
| combining_algoritm | string | optional | Combining algorithm. |
| effect | `io.restorecommerce.access_control.Effect` | optional | A policy's effect (only applicable if there are no rules). |
| has_rules | bool | required | Flag to infer if effect should be considered or not. |
| rules | `io.restorecommerce.rule.RuleRQ` | optional | List of policies bound to a policy set |

`io.restorecommerce.rule.RuleRQ`

| Field | Type | Label | Description |
| ----- | ---- | ----- | ----------- |
| id | string | required | Policy Set ID |
| target | `io.restorecommerce.access_control.Target` | optional | Policy set target |
| effect | `io.restorecommerce.access_control.Effect` | optional | A policy's effect (only applicable if there are no rules). |

#### CRUD Operations

These operations are exposed for Rule, Policy and PolicySet resources.

| Method Name | Request Type | Response Type | Description |
| ----------- | ------------ | ------------- | ------------|
| Create | [ ]`io.restorecommerce.<resource>.<resourceName>` | [ ]`io.restorecommerce.<resource>.<resourceName>` | List of \<resourceName> be created |
| Read | `io.restorecommerce.resourcebase.ReadRequest` | [ ]`io.restorecommerce.<resource>.<resourceName>` | List of \<resourceName> |
| Update | [ ]`io.restorecommerce.<resource>.<resourceName>` | [ ]`io.restorecommerce.<resource>.<resourceName>` | List of \<resourceName> to be updated |
| Upsert | [ ]`io.restorecommerce.<resource>.<resourceName>` | [ ]`io.restorecommerce.<resource>.<resourceName>` | List of \<resourceName> to be created or updated |
| Delete | `io.restorecommerce.resourcebase.DeleteRequest` | `google.protobuf.Empty` | List of resource IDs to be deleted |

For detailed fields of protobuf messages `io.restorecommerce.resourcebase.ReadRequest` and `io.restorecommerce.resourcebase.DeleteRequest` refer [resource-base-interface](https://github.com/restorecommerce/resource-base-interface/).

## Kafka Events

A [Kafka](https://kafka.apache.org/) topic is created for each resource that is specified in the configuration file.
CRUD operations are posted as event messages to the resource's respective topic, using [kafka-client](https://github.com/restorecommerce/kafka-client).

This microservice subscribes to the following Kafka events by topic:

| Topic Name | Event Name | Description |
| ----------- | ------------ | ------------- |
| `io.restorecommerce.command` | `restoreCommand` | used for system restore |
|                              | `resetCommand` | used for system reset |
|                              | `healthCheckCommand` | to get system health check |
|                              | `versionCommand` | to get system version |

List of events emitted to Kafka by this microservice for below topics:

| Topic Name | Event Name | Description |
| ----------- | ------------ | ------------- |
| `io.restorecommerce.command`              | `restoreResponse` | system restore response |
|                                           | `resetResponse` | system reset response |
|                                           | `healthCheckResponse` | system health check response |
|                                           | `versionResponse` | system version response |
| `io.restorecommerce.policy_sets.resource` | `policy_setCreated` | emitted when policy_set is created |
|                                           | `policy_setModified` | emitted when policy_set is modified |
|                                           | `policy_setDeleted` | emitted when policy_set is deleted |
| `io.restorecommerce.policies.resource`    | `policyCreated` | emitted when policy is created |
|                                           | `policyModified` | emitted when policy is modified |
|                                           | `policyDeleted` | emitted when policy is deleted |
| `io.restorecommerce.rules.resource`       | `ruleCreated` | emitted when rule is created |
|                                           | `ruleModified` | emitted when rule is modified |
|                                           | `ruleDeleted` | emitted when rule is deleted |

## Chassis Service

This service uses [chassis-srv](http://github.com/restorecommerce/chassis-srv), a base module for [restorecommerce](https://github.com/restorecommerce) microservices, in order to provide the following functionalities:

- exposure of all previously mentioned gRPC endpoints
- implementation of a [command-interface](https://github.com/restorecommerce/chassis-srv/blob/master/command-interface.md) which
provides endpoints for retrieving the system status and resetting/restoring the system in case of failure. These endpoints can be called via gRPC or Kafka events (through the `io.restorecommerce.command` topic).
- database access, which is abstracted by the [resource-base-interface](https://github.com/restorecommerce/resource-base-interface)
- stores the offset values for Kafka topics at regular intervals to [Redis](https://redis.io/).

## Development

### Tests

See [tests](test/). To execute the tests set of _backing services_ are needed.
Refer to [System](https://github.com/restorecommerce/system) repository to start the backing-services before running the tests.

- To run tests

```sh
npm run test
```

## Running as Docker Container

This service depends on a set of _backing services_ that can be started using a
dedicated [docker compose definition](https://github.com/restorecommerce/system).

```sh
docker run \
 --name restorecommerce_access_control_srv \
 --hostname access-control-srv \
 --network=system_test \
 -e NODE_ENV=production \
 -p 50061:50061 \
 restorecommerce/access-control-srv
```

## Running Locally

Install dependencies

```sh
npm install
```

Build service

```sh
# compile the code
npm run build
```

Start service

```sh
# run compiled service
npm start
```
