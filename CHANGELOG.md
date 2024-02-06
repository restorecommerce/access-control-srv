### 1.2.9 (February 6th, 2024)

- bump deps
- fix tests

### 1.2.8 (November 26th, 2023)

- removed deprecated method in chassis-srv (collection.load)

## 1.2.7 (November 25th, 2023)

- updated all dependencies (added created_by field to meta and client_id to tokens)

## 1.2.6 (November 21st, 2023)

- Support for multiple operations in isAllowed

## 1.2.5 (November 21st, 2023)

- restructure code

## 1.2.4 (November 21st, 2023)

- up deps (for expires_in timestamp changes)

## 1.2.3 (October 21st, 2023)

- on user deletion delete HR scopes and ACS cache

## 1.2.2 (October 11th, 2023)

- fix unit tests (revert the order of attributes match)

## 1.2.1 (October 10th, 2023)

- added filter for rules
- up log message

## 1.2.0 (October 7th, 2023)

- up node and dependencies

## 1.1.1 (September 22nd, 2023)

- added null checks

## 1.1.0 (September 20th, 2023)

- made all fields optionals in proto files

## 1.0.5 (July 28th, 2023)

- use generated server typings

## 1.0.4 (July 26th, 2023)

- updated dependencies

## 1.0.3 (July 26th, 2023)

- fix grpc client logger initialization

## 1.0.2 (July 26th, 2023)

- dependency updates

## 1.0.1 (June 28th, 2023)

- updated depenedencies

## 1.0.0 (June 20th, 2023)

- major version change (considering full typed client server, full text and up all dependencies)

## 0.3.6 (June 19th, 2023)

- up all deps

## 0.3.5 (October 26th, 2022)

- move to full typed client and server, full text search
- up all deps

## 0.3.4 (August 22nd, 2022)

- add null check for redis key exist

## 0.3.3 (July 21st, 2022)

- fix to emit HR scope request only if key does not exist (ex: for superadmin HR scope will be empty and to prevent calculation of HR scope every time)

## 0.3.2 (July 8th, 2022)

- up deps

## 0.3.1 (July 8th, 2022)

- up deps

## 0.3.0 (June 30th, 2022)

- up deps

## 0.2.22 (March 18th, 2022)

- updated acs-client

## 0.2.21 (February 18th, 2022)

- updated chassis-srv (includes fix for offset store config)

## 0.2.20 (February 14th, 2022)

- fixed offset store

## 0.2.19 (February 14th, 2022)

- updated redis url

## 0.2.18 (February 14th, 2022)

- updated dependencies and migrated from ioredis to redis
- added offset store support

## 0.2.17 (February 9th, 2022)

- updated protos

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
