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
 * JUnit Test for {@link PkiResponse} model.
 *
 * @author Stefan Kalscheuer
 */
class PkiResponseTest extends AbstractModelTest<PkiResponse> {
    private static final String LEASE_ID = "pki/issue/test/7ad6cfa5-f04f-c62a-d477-f33210475d05";
    private static final Boolean RES_RENEWABLE = false;
    private static final Integer RES_LEASE_DURATION = 21600;
    private static final Long PKI_EXPIRATION = 1654105687L;
    private static final String PKI_CERTIFICATE = "-----BEGIN CERTIFICATE-----\\nMIIDzDCCAragAwIBAgIUOd0ukLcjH43TfTHFG9qE0FtlMVgwCwYJKoZIhvcNAQEL\\n...\\numkqeYeO30g1uYvDuWLXVA==\\n-----END CERTIFICATE-----\\n";
    private static final String PKI_ISSUING_CA = "-----BEGIN CERTIFICATE-----\\nMIIDUTCCAjmgAwIBAgIJAKM+z4MSfw2mMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV\\n...\\nG/7g4koczXLoUM3OQXd5Aq2cs4SS1vODrYmgbioFsQ3eDHd1fg==\\n-----END CERTIFICATE-----\\n";
    private static final String PKI_CA_CHAIN_0 = "-----BEGIN CERTIFICATE-----\\nMIIDUTCCAjmgAwIBAgIJAKM+z4MSfw2mMA0GCSqGSIb3DQEBCwUAMBsxGTAXBgNV\\n...\\nG/7g4koczXLoUM3OQXd5Aq2cs4SS1vODrYmgbioFsQ3eDHd1fg==\\n-----END CERTIFICATE-----\\n";
    private static final String PKI_PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\\nMIIEowIBAAKCAQEAnVHfwoKsUG1GDVyWB1AFroaKl2ImMBO8EnvGLRrmobIkQvh+\\n...\\nQN351pgTphi6nlCkGPzkDuwvtxSxiCWXQcaxrHAL7MiJpPzkIBq1\\n-----END RSA PRIVATE KEY-----\\n";
    private static final String PKI_PRIVATE_KEY_TYPE = "rsa";
    private static final String PKI_SERIAL_NUMBER = "39:dd:2e:90:b7:23:1f:8d:d3:7d:31:c5:1b:da:84:d0:5b:65:31:58";

    private static final String RES_JSON = "{\n" +
        "  \"lease_id\": \"" + LEASE_ID + "\",\n" +
        "  \"renewable\": " + RES_RENEWABLE + ",\n" +
        "  \"lease_duration\": " + RES_LEASE_DURATION + ",\n" +
        "  \"data\": {\n" +
        "    \"expiration\": \"" + PKI_EXPIRATION + "\",\n" +
        "    \"certificate\": \"" + PKI_CERTIFICATE + "\",\n" +
        "    \"issuing_ca\": \"" + PKI_ISSUING_CA + "\",\n" +
        "    \"ca_chain\": [\n" +
        "      \"" + PKI_CA_CHAIN_0 + "\"\n" +
        "    ],\n" +
        "    \"private_key\": \"" + PKI_PRIVATE_KEY + "\",\n" +
        "    \"private_key_type\": \"" + PKI_PRIVATE_KEY_TYPE + "\",\n" +
        "    \"serial_number\": \"" + PKI_SERIAL_NUMBER + "\"\n" +
        "  },\n" +
        "  \"warnings\": null,\n" +
        "  \"auth\": null\n" +
        "}";

    PkiResponseTest() {
        super(PkiResponse.class);
    }

    @Override
    protected PkiResponse createFull() {
        return assertDoesNotThrow(
            () -> objectMapper.readValue(RES_JSON, PkiResponse.class),
            "Creation of full model instance failed"
        );
    }

    @Test
    void jsonRoundtrip() {
        PkiResponse res = assertDoesNotThrow(
            () -> objectMapper.readValue(RES_JSON, PkiResponse.class),
            "PkiResponse deserialization failed"
        );
        assertNotNull(res, "Parsed response is NULL");
        assertEquals(LEASE_ID, res.responseHeader().leaseId(), "Incorrect leaseId");
        assertEquals(RES_RENEWABLE, res.responseHeader().renewable(), "Incorrect response renewable flag");
        assertEquals(RES_LEASE_DURATION, res.responseHeader().leaseDuration(), "Incorrect leaseDuration");
        assertNull(res.responseHeader().warnings(), "Incorrect warnings");
        assertNull(res.responseHeader().mountType(), "Incorrect mount type");

        PkiResponse.Data data = res.data();
        assertNotNull(data, "PKI data is NULL");
        assertEquals(PKI_EXPIRATION, data.expiration(), "Incorrect pki expiration");
        assertEquals(PKI_CERTIFICATE.replaceAll("\\\\n", "\n"), data.certificate(), "Incorrect pki certificate");
        assertEquals(PKI_ISSUING_CA.replaceAll("\\\\n", "\n"), data.issuingCa(), "Incorrect pki issuingCa");
        assertEquals(List.of(PKI_CA_CHAIN_0.replaceAll("\\\\n", "\n")), data.caChain(), "Incorrect pki caChain");
        assertEquals(PKI_PRIVATE_KEY.replaceAll("\\\\n", "\n"), data.privateKey(), "Incorrect pki privateKey");
        assertEquals(PKI_PRIVATE_KEY_TYPE, data.privateKeyType(), "Incorrect pki privateKeyType");
        assertEquals(PKI_SERIAL_NUMBER, data.serialNumber(), "Incorrect pki serialNumber");
    }
}
