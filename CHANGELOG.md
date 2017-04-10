## 0.6.0 [work in progress]
* [feature] Custom timeout and number of retries (#9)
* [fix] `SecretResponse` does not throw NPE on `get(key)` and `getData()` 

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