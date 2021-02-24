## 0.1.14 (February 24th, 2020)

- updated logger and service config

## 0.1.13 (February 23rd, 2020)

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
