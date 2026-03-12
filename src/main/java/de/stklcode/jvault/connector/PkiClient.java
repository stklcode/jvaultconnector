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

package de.stklcode.jvault.connector;

import de.stklcode.jvault.connector.exception.VaultConnectorException;
import de.stklcode.jvault.connector.model.PkiRequest;
import de.stklcode.jvault.connector.model.response.PkiCaResponse;
import de.stklcode.jvault.connector.model.response.PkiResponse;
import de.stklcode.jvault.connector.model.response.PkiRevocationResponse;

/**
 * PKI client interface.
 * Provides methods to interact with Vault's PKI API.
 *
 * @since 2.0.0
 */
public interface PkiClient {

    /**
     * Generate a new set of credentials (certificate and private key) based on the given role name using.
     * The issuer is determined by role.
     *
     * @param role    The role name
     * @param request The request
     * @return PKI response
     * @throws VaultConnectorException on error
     */
    PkiResponse generateCertificateAndKey(String role, PkiRequest request) throws VaultConnectorException;

    /**
     * Generate a new set of credentials (certificate and private key) based on the given role and issuer.
     *
     * @param issuer  The issuer reference
     * @param role    The role name
     * @param request The request
     * @return PKI response
     * @throws VaultConnectorException on error
     */
    PkiResponse generateCertificateAndKey(String role, String issuer, PkiRequest request) throws VaultConnectorException;

    /**
     * Request revocation of a certificate by serial number.
     *
     * @param serial Serial number of the certificate to revoke, in hyphen-separated or colon-separated hexadecimal
     * @return Revocation response
     * @throws VaultConnectorException on error
     */
    PkiRevocationResponse revokeBySerial(String serial) throws VaultConnectorException;

    /**
     * Request revocation of a certificate by serial number.
     *
     * @param certificate Certificate to revoke, in PEM format
     * @return Revocation response
     * @throws VaultConnectorException on error
     */
    PkiRevocationResponse revokeCertificate(String certificate) throws VaultConnectorException;

    /**
     * Read the default issuer's CA certificate.
     *
     * @return CA/issuer response
     * @throws VaultConnectorException on error
     */
    PkiCaResponse readCaCert() throws VaultConnectorException;

    /**
     * Read the certificate of a specific issuer.
     *
     * @param issuer The issuer reference (may be "default")
     * @return CA/issuer response
     * @throws VaultConnectorException on error
     */
    PkiCaResponse readIssuerCert(String issuer) throws VaultConnectorException;

}
