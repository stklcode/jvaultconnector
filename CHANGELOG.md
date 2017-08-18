## 0.6.2 [work in progress]
* [fix] Prevent potential NPE on SecretResponse getter
* [fix] Fields of InvalidResposneException made final
* [fix] Fix typo in method name `listAppRoleSecrets()` (#14)
* [text] Tested against Vault 0.8.1, increased coverage

## 0.6.1 [2017-08-02]
* [fix] `TokenModel.getPassword()` returned username instead of password
* [fix]  `TokenModel.getUsername()` and `getPassword()` could produce NPE in multithreaded environments
* [fix] `TokenData.getCreatinTtl()` renamed to `getCreationTtl()` (typo fix)
* [test] Tested against Vault 0.7.3

## 0.6.0 [2017-05-12]
* [feature] Initialization from environment variables using `fromEnv()` in factory (#8)
* [feature] Automatic authentication with `buildAndAuth()`
* [feature] Custom timeout and number of retries (#9)
* [feature] Connector implements `AutoCloseable`
* [fix] `SecretResponse` does not throw NPE on `get(key)` and `getData()` 
* [test] Tested against Vault 0.7.2

## 0.5.0 [2017-03-18]
* [feature] Convenience methods for DB credentials (#7)
* [fix] Minor bugfix in TokenBuilder
* [deprecation] `SecretResponse.getValue()` deprecated
* [test] Tested against Vault 0.7.0

## 0.4.1 [2016-12-24]
* [fix] Factory Null-tolerant for trusted certificate (#6)
* [test] StackTraces tested for secret leaks
* [test] Tested against Vault 0.6.4

## 0.4.0 [2016-11-06]
* [feature] Option to provide a trusted CA certificate (#2)
* [feature] Deletion, revocation and renewal of secrets (#3)
* [feature] Token creation (#4)
* [feature] AppRole auth backend supported (#5)
* [improvement] Support for complex secrets
* [deprecation] App-ID backend marked as deprecated

## 0.3.0 [2016-10-07]
* [feature] Retrieval of JSON objects (#1)
* [test] Tested against Vault 0.6.2

## 0.2.0 [2016-09-01]
* Dependecies updated and CommonsIO removed
* [fix] Fixed auth backend detection for Vault 0.6.1
* [test] Tested against Vault 0.6.1

## 0.1.1 [2016-06-20]
* [fix] Check for "permission denied" without status code 400 instead of 403
* [test] Tested against Vault 0.6.0

## 0.1.0 [2016-03-29]
* First release
