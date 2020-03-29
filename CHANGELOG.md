## 0.9.0 (unreleased)

### Fixes
* Correctly parse Map field for token metadata (#34)
* Correctly map token policies on lookup (#35)

### Improvements
* Minor dependency updates


## 0.8.2 (2019-10-20)

### Fixes
* Fixed token lookup (#31) 

### Improvements
* Updated dependencies

## 0.8.1 (2019-08-16)
### Fixes
* Removed compile dependency to JUnit library (#30) 

### Improvements
* Updated dependencies

### Test
* Tested against Vault 1.2.2

## 0.8.0 (2019-03-24)
### Breaking
* Moved Maven artifact to `de.stklcode.jvault:jvault-connector` (#28)
* Removed support for `HTTPVaultConnectorFactory#withSslContext()` in favor of `#withTrustedCA()` due to

### Features
* Support for KV version 2 secret engine (#16)
* Ability to pass custom mount point to KV v2 read/write methods (#25)

### Improvements
* refactoring of the internal SSL handling (#17)
* `VaultConnector` extends `java.io.Serializable` (#19)
* Added missing flags to `SealResponse` (#20)
* Added replication flags to `HealthResponse` (#21)
* Enforce TLS 1.2 by default with option to override (#22)
* Build environment and tests now compatible with Java 10
* Updated dependencies to fix vulnerabilities (i.e. CVE-2018-7489)
* New static method `Token.builder()` to get token builder instance
* New static method `AppRole.builder()` to get AppRole builder instance

### Deprecation
* `VaultConnectorFactory` is deprecated in favor of `VaultConnectorBuilder` with identical API (#18)
* `AppRoleBuilder#withBoundCidrList(List)` is deprecated in favor of `AppRoleBuilder#withSecretIdBoundCidrs(List)` (#24)


## 0.7.1 (2018-03-17)
### Improvements
* Added automatic module name for JPMS compatibility
* Minor dependency updates

### Test
* Tested against Vault 0.9.5


## 0.7.0 (2017-10-03)
### Features
* Retrieval of health status via `getHealth()` (#15)

### Improvements
* `seal()`, `unseal()` are now `void` and throw Exception on error (#12)
* Adaptation to Vault 0.8 endpoints for `renew` and `revoke`, **breaking** 0.7 compatibility (#11)

### Removed
* Removed deprecated `listAppRoleSecretss()` (use `listAppRoleSecrets()`) (#14)

### Test
* Tested against Vault 0.8.3


## 0.6.2 [2017-08-19]
### Fixes
* Prevent potential NPE on SecretResponse getter
* Removed stack traces on PUT request and response deserialization (#13)

### Improvements
* Fields of InvalidResposneException made final

### Deprecation
* `listAppRoleSecretss()` in favor of `listAppRoleSecrets()` (#14)

### Test
* Tested against Vault 0.8.1, increased coverage


## 0.6.1 (2017-08-02)
### Fixes
* `TokenModel.getPassword()` returned username instead of password
* `TokenModel.getUsername()` and `getPassword()` could produce NPE in multithreaded environments
* `TokenData.getCreatinTtl()` renamed to `getCreationTtl()` (typo fix)

### Test
* Tested against Vault 0.7.3


## 0.6.0 (2017-05-12)
### Features
* Initialization from environment variables using `fromEnv()` in factory (#8)
* Automatic authentication with `buildAndAuth()`
* Custom timeout and number of retries (#9)
* Connector implements `AutoCloseable`

### Fixes
* `SecretResponse` does not throw NPE on `get(key)` and `getData()`

### Test 
* Tested against Vault 0.7.2


## 0.5.0 (2017-03-18)
### Features
* Convenience methods for DB credentials (#7)

### Fixes
* Minor bugfix in TokenBuilder

### Deprecation
* `SecretResponse.getValue()` deprecated

### Test
* Tested against Vault 0.7.0


## 0.4.1 [2016-12-24]
### Fixes
* Factory Null-tolerant for trusted certificate (#6)

### Test
* StackTraces tested for secret leaks
* Tested against Vault 0.6.4


## 0.4.0 (2016-11-06)
### Features
* Option to provide a trusted CA certificate (#2)
* Deletion, revocation and renewal of secrets (#3)
* Token creation (#4)
* AppRole auth backend supported (#5)

### Improvements
* Support for complex secrets

### Deprecation
* App-ID backend marked as deprecated


## 0.3.0 (2016-10-07)
### Features
* Retrieval of JSON objects (#1)

### Test
* Tested against Vault 0.6.2


## 0.2.0 (2016-09-01)
### Improvements
* Dependecies updated and CommonsIO removed

### Fixes
* Fixed auth backend detection for Vault 0.6.1

### Test
* Tested against Vault 0.6.1


## 0.1.1 (2016-06-20)
### Fixes
* Check for "permission denied" without status code 400 instead of 403

### Test
* Tested against Vault 0.6.0


## 0.1.0 (2016-03-29)
* First release
