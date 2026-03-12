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

package de.stklcode.jvault.connector.model.response;

import de.stklcode.jvault.connector.model.AbstractModelTest;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JUnit Test for {@link PkiCaResponse} model.
 *
 * @author Stefan Kalscheuer
 */
class PkiCaResponseTest extends AbstractModelTest<PkiCaResponse> {
    private static final String LEASE_ID = "pki/ca/cert/1e26c095-b50e-483e-ab63-07612e6d6602";
    private static final Boolean RES_RENEWABLE = false;
    private static final Integer RES_LEASE_DURATION = 21600;
    private static final String AUTH_KEY_ID = "8b:e4:1a:d9:63:cf:8f:2b:e0:54:97:11:7c:da:02:f3:6a:5e:bc:4d";
    private static final String PEM_1 = "-----BEGIN CERTIFICATE-----\\nMIIDUTCCAjmgAwIBAgIJAKM+z4MSfw2mMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV\\n...\\nG/7g4koczXLoUM3OQXd5Aq2cs4SS1vODrYmgbioFsQ3eDHd1fg==\\n-----END CERTIFICATE-----\\n";
    private static final String PEM_2 = "-----BEGIN CERTIFICATE-----\\nMIIDLTCCAhWgAwIBAgIUQJcpa6gCLJWt+TowyNwVrdrjKlgwDQYJKoZIhvcNAQEL\\n...\\nTQ==\\n-----END CERTIFICATE-----\\n";
    private static final String ISSUER_ID = "fd10c11b-d5aa-4fb4-9ea2-94741e0b5f98";
    private static final String ISSUER_NAME = "my-issuer";

    private static final String RES_CA_JSON = "{\n" +
        "  \"lease_id\": \"" + LEASE_ID + "\",\n" +
        "  \"renewable\": " + RES_RENEWABLE + ",\n" +
        "  \"lease_duration\": " + RES_LEASE_DURATION + ",\n" +
        "  \"data\": {\n" +
        "    \"authority_key_id\": \"" + AUTH_KEY_ID + "\",\n" +
        "    \"certificate\": \"" + PEM_2 + "\",\n" +
        "    \"revocation_time\": 0,\n" +
        "    \"revocation_time_rfc3339\": \"\"\n" +
        "  },\n" +
        "  \"warnings\": null,\n" +
        "  \"auth\": null\n" +
        "}";
    private static final String RES_ISSUER_JSON = "{\n" +
        "  \"lease_id\": \"" + LEASE_ID + "\",\n" +
        "  \"renewable\": " + RES_RENEWABLE + ",\n" +
        "  \"lease_duration\": " + RES_LEASE_DURATION + ",\n" +
        "  \"data\": {\n" +
        "    \"ca_chain\": [" +
        "      \"" + PEM_1 + "\",\n" +
        "      \"" + PEM_2 + "\"\n" +
        "    ],\n" +
        "    \"certificate\": \"" + PEM_1 + "\",\n" +
        "    \"issuer_id\": \"" + ISSUER_ID + "\",\n" +
        "    \"issuer_name\": \"" + ISSUER_NAME + "\"\n" +
        "  },\n" +
        "  \"warnings\": null,\n" +
        "  \"auth\": null\n" +
        "}";

    PkiCaResponseTest() {
        super(PkiCaResponse.class);
    }

    @Override
    protected PkiCaResponse createFull() {
        return assertDoesNotThrow(
            () -> objectMapper.readValue(RES_CA_JSON, PkiCaResponse.class),
            "Creation of full model instance failed"
        );
    }

    @Test
    void jsonRoundtripCa() {
        PkiCaResponse res = assertDoesNotThrow(
            () -> objectMapper.readValue(RES_CA_JSON, PkiCaResponse.class),
            "PkiCaResponse deserialization failed"
        );
        assertNotNull(res, "Parsed response is NULL");
        assertEquals(LEASE_ID, res.responseHeader().leaseId(), "Incorrect leaseId");
        assertEquals(RES_RENEWABLE, res.responseHeader().renewable(), "Incorrect response renewable flag");
        assertEquals(RES_LEASE_DURATION, res.responseHeader().leaseDuration(), "Incorrect leaseDuration");
        assertNull(res.responseHeader().warnings(), "Incorrect warnings");
        assertNull(res.responseHeader().mountType(), "Incorrect mount type");

        PkiCaResponse.Data data = res.data();
        assertNotNull(data, "PKI data is NULL");
        assertEquals(AUTH_KEY_ID, data.authorityKeyId(), "Incorrect authorityKeyId");
        assertEquals(PEM_2.replaceAll("\\\\n", "\n"), data.certificate(), "Incorrect certificate");
        assertEquals(0, data.revocationTime(), "Incorrect revocationTime");
        assertEquals("", data.revocationTimeRFC3339(), "Incorrect revocationTimeRFC3339");
        assertNull(data.caChain(), "Incorrect caChain");
        assertNull(data.issuerId(), "Incorrect issuerId");
        assertNull(data.issuerName(), "Incorrect issuerName");
    }

    @Test
    void jsonRoundtripIssuer() {
        PkiCaResponse res = assertDoesNotThrow(
            () -> objectMapper.readValue(RES_ISSUER_JSON, PkiCaResponse.class),
            "PkiCaResponse deserialization failed"
        );
        assertNotNull(res, "Parsed response is NULL");

        PkiCaResponse.Data data = res.data();
        assertNotNull(data, "PKI data is NULL");
        assertNull(data.authorityKeyId(), "Incorrect authorityKeyId");
        assertEquals(PEM_1.replaceAll("\\\\n", "\n"), data.certificate(), "Incorrect certificate");
        assertNull(data.revocationTime(), "Incorrect revocationTime");
        assertNull(data.revocationTimeRFC3339(), "Incorrect revocationTimeRFC3339");
        assertEquals(
            List.of(
                PEM_1.replaceAll("\\\\n", "\n"),
                PEM_2.replaceAll("\\\\n", "\n")
            ),
            data.caChain(),
            "Incorrect caChain"
        );
        assertEquals(ISSUER_ID, data.issuerId(), "Incorrect issuerId");
        assertEquals(ISSUER_NAME, data.issuerName(), "Incorrect issuerName");
    }
}
