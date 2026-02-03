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
import de.stklcode.jvault.connector.model.response.TransitResponse;

import java.util.Base64;

/**
 * Transit client interface.
 * Provides methods to interact with Vault's transit API.
 *
 * @since 2.0.0 extracted from {@link VaultConnector}
 */
public interface TransitClient {

    /**
     * Encrypt plaintext via transit engine from Vault.
     *
     * @param keyName   Transit key name
     * @param plaintext Text to encrypt (Base64 encoded)
     * @return Transit response
     * @throws VaultConnectorException on error
     * @since 1.5.0
     */
    TransitResponse encrypt(final String keyName, final String plaintext) throws VaultConnectorException;

    /**
     * Encrypt plaintext via transit engine from Vault.
     *
     * @param keyName   Transit key name
     * @param plaintext Binary data to encrypt
     * @return Transit response
     * @throws VaultConnectorException on error
     * @since 1.5.0
     */
    default TransitResponse encrypt(final String keyName, final byte[] plaintext)
        throws VaultConnectorException {
        return encrypt(keyName, Base64.getEncoder().encodeToString(plaintext));
    }

    /**
     * Decrypt ciphertext via transit engine from Vault.
     *
     * @param keyName    Transit key name
     * @param ciphertext Text to decrypt
     * @return Transit response
     * @throws VaultConnectorException on error
     * @since 1.5.0
     */
    TransitResponse decrypt(final String keyName, final String ciphertext) throws VaultConnectorException;

    /**
     * Hash data in hex format via transit engine from Vault.
     *
     * @param algorithm Specifies the hash algorithm to use
     * @param input     Data to hash
     * @return Transit response
     * @throws VaultConnectorException on error
     * @since 1.5.0
     */
    default TransitResponse hash(final String algorithm, final String input) throws VaultConnectorException {
        return hash(algorithm, input, "hex");
    }

    /**
     * Hash data via transit engine from Vault.
     *
     * @param algorithm Specifies the hash algorithm to use
     * @param input     Data to hash (Base64 encoded)
     * @param format    Specifies the output encoding (hex/base64)
     * @return Transit response
     * @throws VaultConnectorException on error
     * @since 1.5.0
     */
    TransitResponse hash(final String algorithm, final String input, final String format)
        throws VaultConnectorException;

    /**
     * Hash data via transit engine from Vault.
     *
     * @param algorithm Specifies the hash algorithm to use
     * @param input     Data to hash
     * @return Transit response
     * @throws VaultConnectorException on error
     * @since 1.5.0
     */
    default TransitResponse hash(final String algorithm, final byte[] input, final String format)
        throws VaultConnectorException {
        return hash(algorithm, Base64.getEncoder().encodeToString(input), format);
    }
}
