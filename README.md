# Java Vault Connector 

[![Build Status](https://travis-ci.org/stklcode/jvaultconnector.svg?branch=master)](https://travis-ci.org/stklcode/jvaultconnector)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/stklcode/jvaultconnector/blob/master/LICENSE.txt) 
[![Maven Central](https://img.shields.io/maven-central/v/de.stklcode.jvault/connector.svg)](https://search.maven.org/#search%7Cga%7C1%7Cg%3A%22de.stklcode.jvault%22%20AND%20a%3A%22connector%22)

Java Vault Connector is a connector library for [Vault](https://www.vaultproject.io) by [Hashicorp](https://www.hashicorp.com) written in Java. The connector allows simple usage of Vault's secret store in own applications.

## Features:

* HTTP(S) backend connector
    *  Ability to provide or enforce custom CA certificate
* Authorization methods:
    * Token
    * Username/Password
    * AppID (register and authenticate) [_deprecated_]
    * AppRole (register and authenticate)
* Tokens
    * Creation and lookup of tokens
    * TokenBuilder for speaking creation of complex configuraitons
* Secrets
    * Read secrets
    * Write secrets
    * List secrets
    * Delete secrets
    * Renew/revoke leases
    * Raw secret content or JSON decoding
* Connector Factory with builder pattern
* Tested against Vault 0.6.4

## Usage Example

```java
// Instantiate using builder pattern style factory
VaultConnector vault = VaultConnectorFactory.httpFactory()
 .withHost("127.0.0.1")
 .withPort(8200)
 .withTLS()
 .build();

// Authenticate with token
vault.authToken("01234567-89ab-cdef-0123-456789abcdef");

// Retrieve secret
String secret = vault.readSecret("some/secret/key").getValue();
```

## Maven Artifact
```
<dependency>
    <groupId>de.stklcode.jvault</groupId>
    <artifactId>connector</artifactId>
    <version>0.4.1</version>
</dependency>
```

## Links

[Project Page](http://jvault.stklcode.de)

[JavaDoc API](http://jvault.stklcode.de/apidocs/)

## Planned features

* Creation and modification of policies
* Implement more authentication methods

## License

The project is licensed under [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0).
