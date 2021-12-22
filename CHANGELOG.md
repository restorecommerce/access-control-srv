## 0.2.16 (December 22nd, 2021)

- removed importHelpers flag from tsconfig

### 0.2.15 (December 22nd, 2021)

- updated ts config and added no floating promise rule

### 0.2.14 (December 22nd, 2021)

- updated RC dependencies

## 0.2.13 (December 21st, 2021)

- up RC dependencies

## 0.2.12 (December 15th, 2021)

- up acs-client and other dependencies

## 0.2.11 (December 13th, 2021)

- Added null check for context object

## 0.2.10 (December 10th, 2021)

- fixed custom args response

## 0.2.9 (December 10th, 2021)

- Added typing

## 0.2.8 (December 10th, 2021)

- Added Obligation (Attribute []) for both isAllowed and whatIsAllowed response
- Added properties match for Target resources (for both isAllowed and whatIsAllowed), for isAllowed there will be a DENY if properties mismatch and
  for whatIsAllowed the masked properties are set in Obligation

## 0.2.7 (October 12th, 2021)

- fixed context query filters

## 0.2.6 (October 7th, 2021)

- updated acs-client

## 0.2.5 (October 7th, 2021)

- updated protos (includes `acl` property for ACL validation)

## 0.2.4 (September 27th, 2021)

- fix load policy sets

## 0.2.3 (September 21st, 2021)

- up RC dependencies

## 0.2.2 (September 14th, 2021)

- fix ACL bug to keep track of already validated traget instances

## 0.2.1 (September 13th, 2021)

- up dependencies

## 0.2.0 (August 10th, 2021)

- latest grpc-client
- migraged kafka-client to kafkajs
- chassis-srv using the latest grpc-js and protobufdef loader
- filter changes (removed google.protobuf.struct completely and defined nested proto structure)
- added status object to each item and also overall operation_status.

## 0.1.22 (July 26th, 2021)

- added `skipACL` attribute to support not to make ACL check if this attribute is set in rule
- updated logger

## 0.1.21 (July 21st, 2021)

- added access control list feature for `isAllowed` operation
- updated dependencies

## 0.1.20 (June 28th, 2021)

- updated node version to 16.3
- updated logger and protos

## 0.1.19 (April 28th, 2021)

- extend HR scope matching to check for operation name
- improved logging

## 0.1.18 (April 27th, 2021)

- fix not to load rules / policies that do not exist
- improved logging

## 0.1.17 (March 23rd, 2021)

- fix to compare attributes id and values
- fix flushCache

## 0.1.16 (March 22nd, 2021)

- emit flushCache command to flush acs cache when subject role associations are modified
- migrate from redis to ioredis
- update dependencies

## 0.1.15 (March 11th, 2021)

- updated dependencies

## 0.1.14 (February 24th, 2021)

- updated logger and service config

## 0.1.13 (February 23rd, 2021)

- updated deps, node and npm version
- fix redis set for null check

## 0.1.12 (December 15th, 2020)

- fix to remove empty HR scope check (super_admin)

## 0.1.11 (December 10th, 2020)

- fix to compare token scopes and not complete object

## 0.1.10 (December 2nd, 2020)

- up acs-client (unauthenticated fix), protos (last_login updated on token)

## 0.1.9 (December 2nd, 2020)

- fix docker image permissions

### 0.1.8 (November 19th, 2020)

- fix to set subjectID from findByToken operation
- updated to store HR scopes to redis considering interactive flag
- moved HR scopes request and response messages to auth.proto
- updated dependencies

### 0.1.7 (October 19th, 2020)

- updated chassis-srv
- updated acs-client

### 0.1.6 (October 14th, 2020)

- add new grpc healthcheck with readiness probe
- listen on 0.0.0.0 for grpc port
- add evaluation_cacheable for isAllowed and whatIsAllowed
- updated acs-client and protos

### 0.1.5 (October 9th, 2020)

- up acs-client includes the fix for validation of token and subjectid
- fix if subject does not exist in redis

### 0.1.4 (October 3rd, 2020)

- changes to store HR scope to redis with different key based on token if scopes for token exist
- update for resturctured protos

### 0.1.3 (September 9th, 2020)

- changes to create HR scope and storing it in redis

### 0.1.2 (Auguest 27th, 2020)

- healthcheck fix, updated dependencies

### 0.1.1 (Auguest 18th, 2020)

- updated logger and node version

### 0.1.0 (July 29th, 2020)

- initial release
