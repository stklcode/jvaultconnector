# Java Vault Connector

[![CI](https://github.com/stklcode/jvaultconnector/actions/workflows/ci.yml/badge.svg)](https://github.com/stklcode/jvaultconnector/actions/workflows/ci.yml)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=de.stklcode.jvault%3Ajvault-connector&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=de.stklcode.jvault%3Ajvault-connector)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/stklcode/jvaultconnector/blob/main/LICENSE.txt)
[![Maven Central Version](https://img.shields.io/maven-central/v/de.stklcode.jvault/jvault-connector)](https://central.sonatype.com/artifact/de.stklcode.jvault/jvault-connector)

![Logo](assets/logo.png)

Java Vault Connector is a connector library for [Vault](https://www.vaultproject.io) by [Hashicorp](https://www.hashicorp.com) written in Java. The connector allows simple usage of Vault's secret store in own applications.

## Features:

* HTTP(S) backend connector
    * Ability to provide or enforce custom CA certificate
    * Optional initialization from environment variables
* Authorization methods
    * Token
    * Username/Password
    * AppRole (register and authenticate)
* Tokens
    * Creation and lookup of tokens and token roles
    * TokenBuilder for speaking creation of complex configurations
* Secrets
    * Read secrets
    * Write secrets
    * List secrets
    * Delete secrets
    * Renew/revoke leases
    * Raw secret content or JSON decoding
    * KV v1 and v2 support
    * Database secret handling
* Transit API support
* Connector Factory with builder pattern
* Tested against Vault 1.2 to 1.20


## Maven Artifact
```xml
<dependency>
    <groupId>de.stklcode.jvault</groupId>
    <artifactId>jvault-connector</artifactId>
    <version>1.5.1</version>
</dependency>
```

## Usage Examples

### Initialization

```java
// Instantiate using builder pattern style factory (TLS enabled by default)
VaultConnector vault = HTTPVaultConnector.builder()
 .withHost("127.0.0.1")
 .withPort(8200)
 .withTLS()
 .build();

// Instantiate with custom SSL context
VaultConnector vault = HTTPVaultConnector.builder("https://example.com:8200/v1/")
 .withTrustedCA(Paths.get("/path/to/CA.pem"))
 .build();

// Initialization from environment variables
VaultConnector vault = HTTPVaultConnector.builder()
 .fromEnv()
 .build();
```

### Authentication

```java
// Authenticate with token.
vault.authToken("01234567-89ab-cdef-0123-456789abcdef");

// Authenticate with username and password.
vault.authUserPass("username", "p4ssw0rd");

// Authenticate with AppRole (secret - 2nd argument - is optional).
vault.authAppRole("01234567-89ab-cdef-0123-456789abcdef", "fedcba98-7654-3210-fedc-ba9876543210");
```

### Secret read & write

```java
// Retrieve secret (prefix "secret/" assumed, use read() to read arbitrary paths)
String secret = vault.read("secret/some/key").get("value", String.class);

// Complex secret.
Map<String, Object> secretData = vault.read("secret/another/key").getData();

// Write simple secret.
vault.write("secret/new/key", "secret value");

// Write complex data.
Map<String, Object> map = ...;
vault.write("path/to/write", map);

// Delete secret.
vault.delete("path/to/delete");
```

### Token and role creation

```java
// Create token using TokenBuilder
Token token = Token.builder()
                   .withId("token id")
                   .withDisplayName("new test token")
                   .withPolicies("pol1", "pol2")
                   .build();
vault.createToken(token);

// Create AppRole credentials
vault.createAppRole("testrole", policyList);
AppRoleSecretResponse secret = vault.createAppRoleSecret("testrole");
```

## Links

[Project Page](https://jvault.stklcode.de)

[JavaDoc API](https://jvault.stklcode.de/apidocs/)

## License

The project is licensed under [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).
