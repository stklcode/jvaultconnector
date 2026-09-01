/*
 * Copyright 2016-2026 Stefan Kalscheuer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package de.stklcode.jvault.connector.it;

import de.stklcode.jvault.connector.exception.*;
import de.stklcode.jvault.connector.model.*;
import de.stklcode.jvault.connector.model.response.*;
import org.junit.jupiter.api.*;

import java.io.*;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Integration tests for HTTP Vault connector PKI module.
 */
@DisplayName("PKI Tests")
class HTTPVaultConnectorPkiIT extends HTTPVaultConnectorITBase {

    private static final String PKI_CA_PEM = """
        -----BEGIN CERTIFICATE-----
        MIIDLTCCAhWgAwIBAgIUIk5Ftm69U+MrzKZ5wVrgzsw2GUcwDQYJKoZIhvcNAQEL
        BQAwHjEcMBoGA1UEAxMTSlZhdWx0IFRlc3QgUm9vdCBDQTAeFw0yNjA4MTgxNjAz
        MzJaFw0zNjA4MTUxNjA0MDJaMB4xHDAaBgNVBAMTE0pWYXVsdCBUZXN0IFJvb3Qg
        Q0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCYbl79aCEAnrpAHzWZ
        iHMN4ifHNbre5UZUJebvXW0VHdv1fck5ISdRdBnvA5NV5U0513aQ7IyxPkhJ/AGQ
        XDN8CGXc+EzanFY/OE0NRXcslh3DAEGG2XdSOj1E5qDBW4FPleR+3HnEDHS80VPx
        r/Dzp9ocdRNHU1/L9kiGIAD6PKu+N1qGwk7nHRhNN0DA+eEugCKqSvmzc44kWv1X
        edES7gW8V2lBnexelvmWTuCtugkbAv65bNXtUbG6TrU6SnC7xjHbnTbFSE5P3y8R
        F84KqxEV7t1YGMUH/cyP2SBgr4ov0gY8zk/ztFpB6t7kKudkmfN6bTOXA7lkR+1I
        lfg7AgMBAAGjYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0G
        A1UdDgQWBBSbtEvMeGN31R4EUsm845meQv3+LjAfBgNVHSMEGDAWgBSbtEvMeGN3
        1R4EUsm845meQv3+LjANBgkqhkiG9w0BAQsFAAOCAQEAdcrUEHPrBb6gxiZG9YID
        JjeM1BIb4X2Xl+Y3smrIM4XnOoMAgVEbO5wk7Ay8S7FzkwZj+4PGB69PXSlLfxMU
        c4UQ7OJA6dNDfgIIe2+epJY0uta3/17WAFmTc/zpDLVCvRAyURjmubxSZOQBHFPW
        5wt6P9wRVbdvVnN4vSrcXinCOzMOldoBtBH8nvoQk0BNvOqDiKlsvtzjEdcOpJ+H
        9lbB1XthaemInfDWFFcy2LczT3jgUnfhQpkXFoqxjg8RQPhom4TMg/oNwdpy3SST
        pOYbrmJac/PjsnAlKAF4ZX+C9C6/n88UIXI1znomBsXKQSODPRQnR+Qv1i70Z6IJ
        3w==
        -----END CERTIFICATE-----""";

    @BeforeEach
    void authorize() {
        Assertions.assertDoesNotThrow(() -> connector.authToken(TOKEN_ROOT));
        Assumptions.assumeTrue(connector.isAuthorized());
    }

    @Test
    @DisplayName("Generate certificate and key")
    void generateCertificateAndKeyTest() {
        PkiResponse pkiResponse = Assertions.assertDoesNotThrow(
            () -> connector.pki().generateCertificateAndKey(
                "example-com",
                PkiRequest.builder()
                    .withCommonName("test.example.com")
                    .withAltNames("test2.example.com")
                    .withIpSans("192.0.2.1")
                    .withKeyFormat(PkiRequest.KeyFormat.PKCS8)
                    .build()
            ),
            "Failed to issue certificate"
        );

        assertEquals("rsa", pkiResponse.data().privateKeyType(), "unexpected private key type");
        assertTrue(pkiResponse.data().expiration() > System.currentTimeMillis() / 1000L, "expiration timestamp should be in future");

        assertEquals(PKI_CA_PEM, pkiResponse.data().issuingCa(), "unexpected issuing CA certificate");
        if (compareVersions(VAULT_VERSION, "1.11.0") >= 0) {
            assertEquals(List.of(PKI_CA_PEM), pkiResponse.data().caChain(), "unexpected CA chain");
        }

        PublicKey caCert = parseCertificate(PKI_CA_PEM).getPublicKey();
        X509Certificate cert = parseCertificate(pkiResponse.data().certificate());
        assertNotNull(cert, "failed o parse certificate");
        assertNotNull(parsePrivateKey(pkiResponse.data().privateKey()), "failed o parse private key");
        assertDoesNotThrow(() -> cert.verify(caCert), "certificate was not signed by the issuing CA");

        assertHasSAN(cert, 2, "test.example.com");
        assertHasSAN(cert, 2, "test2.example.com");
        assertHasSAN(cert, 7, "192.0.2.1");
    }

    @Test
    @DisplayName("Revoke certificates")
    void revokeCertificateAndKeyTest() {
        // First, generate two certificates
        PkiResponse pkiResponse1 = Assertions.assertDoesNotThrow(
            () -> connector.pki().generateCertificateAndKey("example-com",
                PkiRequest.builder().withCommonName("a.example.com").build()),
            "Failed to issue certificate 1"
        );
        PkiResponse pkiResponse2 = Assertions.assertDoesNotThrow(
            () -> connector.pki().generateCertificateAndKey("example-com",
                PkiRequest.builder().withCommonName("b.example.com").build()),
            "Failed to issue certificate 2"
        );

        // Revoke first by serial
        PkiRevocationResponse res1 = Assertions.assertDoesNotThrow(
            () -> connector.pki().revokeBySerial(pkiResponse1.data().serialNumber()),
            "Failed to revoke certificate 1 by serial"
        );
        assertNotNull(res1.data().revocationTime(), "missing revocation time in response");
        assertNotNull(res1.data().revocationTimeRFC3339(), "missing revocation time (RFC 3339) in response");
        if (compareVersions(VAULT_VERSION, "1.14.0") >= 0) {
            assertEquals("revoked", res1.data().state(), "unexpected state in response");
        }

        if (compareVersions(VAULT_VERSION, "1.12.0") >= 0) {
            // Revoke second by certificate
            PkiRevocationResponse res2 = Assertions.assertDoesNotThrow(
                () -> connector.pki().revokeCertificate(pkiResponse2.data().certificate()),
                "Failed to revoke certificate 2 by PEM"
            );
            assertNotNull(res2.data().revocationTime(), "missing revocation time in response");
            assertNotNull(res2.data().revocationTimeRFC3339(), "missing revocation time (RFC 3339) in response");

            if (compareVersions(VAULT_VERSION, "1.14.0") >= 0) {
                assertEquals("revoked", res2.data().state(), "unexpected state in response");
            }
        }

        InvalidResponseException ex = assertThrows(InvalidResponseException.class,
            () -> connector.pki().revokeBySerial("00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00"),
            "Expected exception on revoking non-existent certificate");
        assertEquals(400, ex.getStatusCode(), "unexpected status code in response");
        assertTrue(ex.getResponse().startsWith("certificate with serial 00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00 not found"),
            "unexpected error response message");
    }

    @Test
    @DisplayName("Generate certificate and key with specific issuer")
    void generateCertificateAndKeyWithIssuerTest() {
        assumeTrue(
            compareVersions(VAULT_VERSION, "1.11.0") >= 0,
            "Issuer-specific certificate issuance requires Vault 1.11.0 or later"
        );

        // "default" is always a valid issuer_ref, even without naming a custom issuer
        PkiResponse pkiResponse = Assertions.assertDoesNotThrow(
            () -> connector.pki().generateCertificateAndKey(
                "default",
                "example-com",
                PkiRequest.builder().withCommonName("issuer-test.example.com").build()
            ),
            "Failed to issue certificate via issuer-specific endpoint"
        );

        PublicKey caCert = parseCertificate(PKI_CA_PEM).getPublicKey();
        X509Certificate cert = parseCertificate(pkiResponse.data().certificate());
        assertNotNull(cert, "failed to parse certificate");
        assertDoesNotThrow(() -> cert.verify(caCert), "certificate was not signed by the issuing CA");
        assertHasSAN(cert, 2, "issuer-test.example.com");

        // Requesting an issuer that does not exist
        InvalidResponseException ex = assertThrows(
            InvalidResponseException.class,
            () -> connector.pki().generateCertificateAndKey(
                "bogus-issuer",
                "example-com",
                PkiRequest.builder().withCommonName("wont-issue.example.com").build()
            ),
            "Expected exception when referencing a non-existent issuer"
        );
        assertTrue(
            ex.getResponse() != null && ex.getResponse().toLowerCase().contains("issuer"),
            "Expected error to reference the invalid issuer, got: " + ex.getResponse()
        );
    }

    @Test
    @DisplayName("Read CA/issuer certificate")
    void readCaCertificateTest() {
        PkiCaResponse pkiResponse = Assertions.assertDoesNotThrow(() -> connector.pki().readCaCert(),
            "Failed to read CA certificate");

        assertEquals(PKI_CA_PEM, pkiResponse.data().certificate(), "unexpected CA certificate");
        assertEquals(0, pkiResponse.data().revocationTime(), "unexpected revocation time");
        assertNull(pkiResponse.data().issuerId(), "unexpected issuer ID");
        assertNull(pkiResponse.data().issuerName(), "unexpected issuer name");

        if (pkiResponse.data().authorityKeyId() != null) {
            // Available in Vault 1.21.1+, but not in OpenBao (checked with 2.6.0)
            assertEquals("9b:b4:4b:cc:78:63:77:d5:1e:04:52:c9:bc:e3:99:9e:42:fd:fe:2e",
                pkiResponse.data().authorityKeyId(),
                "unexpected authority key ID");
        }

        if (compareVersions(VAULT_VERSION, "1.11.0") >= 0) {
            assertEquals("", pkiResponse.data().revocationTimeRFC3339(), "unexpected revocation time (RFC 3339)");

            // Request a specific issuer
            pkiResponse = Assertions.assertDoesNotThrow(() -> connector.pki().readIssuerCert("default"),
                "Failed to read issuer certificate");

            assertEquals(PKI_CA_PEM + "\n", pkiResponse.data().certificate(), "unexpected CA certificate");
            assertEquals(List.of(PKI_CA_PEM + "\n"), pkiResponse.data().caChain(), "unexpected CA chain");
            assertNull(pkiResponse.data().revocationTime(), "unexpected revocation time");
            assertNull(pkiResponse.data().revocationTimeRFC3339(), "unexpected revocation time (RFC 3339)");
            // Issuers are not initialized in Vaul 1.3.0 test data, so dynamically assigned during upgrade
            assertNotNull(pkiResponse.data().issuerId(), "unexpected issuer ID");
            assertNotNull(pkiResponse.data().issuerName(), "unexpected issuer name");
        }
    }

    private static X509Certificate parseCertificate(String pem) {
        try {
            return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(pem.getBytes(UTF_8)));
        } catch (CertificateException e) {
            fail("Failed to parse certificate", e);
            return null;
        }
    }

    private static PrivateKey parsePrivateKey(String pem) {
        try {
            return KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(
                    Base64.getDecoder().decode(
                        pem
                            .replace("-----BEGIN PRIVATE KEY-----", "")
                            .replaceAll(System.lineSeparator(), "")
                            .replace("-----END PRIVATE KEY-----", "")
                            .replaceAll("\\s", ""))
                ));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            fail("Failed to parse private key", e);
            return null;
        }
    }

    private static void assertHasSAN(X509Certificate cert, Integer type, String san) {
        var rawSans = assertDoesNotThrow(cert::getSubjectAlternativeNames, "unable to extract SANs from certificate");
        assertNotNull(rawSans, "missing SANs in certificate");
        for (var item : rawSans) {
            if (item.size() == 2 && type.equals(item.get(0)) && san.equals(item.get(1))) {
                return;
            }
        }

        fail("certificate does not contain SAN of type " + type + " and value " + san);
    }
}
