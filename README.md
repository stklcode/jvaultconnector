Java Vault Connector
=========
Java Vault Connector is a connector library for [Vault](https://www.vaultproject.io) by [Hashicorp](https://www.hashicorp.com) written in Java. The connector allows simple usage of Vault's secret store in own applications.

**Current available features:**

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

**Usage Example**

```java
// Instanciate using builder pattern style factory
VaultConnector vault = VaultConnectorFactory.httpFactory()
 .withHost("127.0.0.1")
 .withPort(8200)
 .withTLS()
 .build();

//authenticate with token
vault.authToken("01234567-89ab-cdef-0123-456789abcdef");

// retrieve secret
String secret = vault.readSecret("some/secret/key").getValue();
```

**Maven Artifact**
```
<dependency>
    <groupId>de.stklcode.jvault</groupId>
    <artifactId>connector</artifactId>
    <version>0.4.0</version>
</dependency>
```

**Links**

[Project Page](http://jvault.stklcode.de)

[JavaDoc API](http://jvault.stklcode.de/apidocs/)

**Planned features:**

* Creation and modification of policies
* Implement more authentication methods

**License**

The project is licensed under [Apache License 2.0](http://www.apache.org/licenses/LICENSE-2.0).
