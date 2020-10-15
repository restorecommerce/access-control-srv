### 0.1.7 (October 15th, 2020)

- updated chassis-srv

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
