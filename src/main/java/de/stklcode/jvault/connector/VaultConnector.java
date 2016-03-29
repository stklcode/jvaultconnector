package de.stklcode.jvault.connector;

import de.stklcode.jvault.connector.exception.VaultConnectorException;
import de.stklcode.jvault.connector.model.AuthBackend;
import de.stklcode.jvault.connector.model.response.SealResponse;
import de.stklcode.jvault.connector.model.response.SecretResponse;
import de.stklcode.jvault.connector.model.response.TokenResponse;
import de.stklcode.jvault.connector.model.response.AuthResponse;

import java.util.List;

/**
 * Vault Connector interface.
 * Provides methods to connect with Vault backend and handle secrets.
 *
 * @author  Stefan Kalscheuer
 * @since   0.1
 */
public interface VaultConnector {
    /**
     * Verify that vault connection is initialized.
     * @return      TRUE if correctly initialized
     */
    boolean init();

    /**
     * Reset authorization information.
     */
    void resetAuth();

    /**
     * Retrieve status of vault seal.
     * @return  Seal status
     */
    SealResponse sealStatus();

    /**
     * Seal vault.
     * @return          TRUE on success
     */
    boolean seal();

    /**
     * Unseal vault.
     * @param key       A single master share key
     * @param reset     Discard previously provided keys (optional)
     * @return          TRUE on success
     */
    SealResponse unseal(final String key, final Boolean reset);

    /**
     * Unseal vault.
     * @param key       A single master share key
     * @return          TRUE on success
     */
    default SealResponse unseal(final String key) {
        return unseal(key, null);
    }

    /**
     * Get all availale authentication backends.
     * @return  List of backends
     */
    List<AuthBackend> getAuthBackends() throws VaultConnectorException;

    /**
     * Authorize to Vault using token.
     * @param token     The token
     * @return          Token response
     */
    TokenResponse authToken(final String token) throws VaultConnectorException;

    /**
     * Authorize to Vault using username and password.
     * @param username  The username
     * @param password  The password
     * @return          Authorization result
     * @throws VaultConnectorException
     */
    AuthResponse authUserPass(final String username, final String password) throws VaultConnectorException;

    /**
     * Authorize to Vault using AppID method.
     * @param appID     The App ID
     * @param userID    The User ID
     * @return          TRUE on success
     */
    AuthResponse authAppId(final String appID, final String userID) throws VaultConnectorException;

    /**
     * Register new App-ID with policy.
     * @param appID         The unique App-ID
     * @param policy        The policy to associate with
     * @param displayName   Arbitrary name to display
     * @return              TRUE on success
     * @throws VaultConnectorException
     */
    boolean registerAppId(final String appID, final String policy, final String displayName) throws VaultConnectorException;

    /**
     * Register User-ID with App-ID
     * @param appID     The App-ID
     * @param userID    The User-ID
     * @return          TRUE on success
     * @throws VaultConnectorException
     */
    boolean registerUserId(final String appID, final String userID) throws VaultConnectorException;

    /**
     * Register new App-ID and User-ID at once.
     * @param appID         The App-ID
     * @param policy        The policy to associate with
     * @param displayName   Arbitrary name to display
     * @param userID        The User-ID
     * @return              TRUE on success
     * @throws VaultConnectorException
     */
    default boolean registerAppUserId(final String appID, final String policy, final String displayName, final String userID) throws VaultConnectorException {
        return registerAppId(appID, policy, userID) && registerUserId(appID, userID);
    }

    /**
     * Get authorization status
     * @return  TRUE, if successfully authorized
     */
    boolean isAuthorized();

    /**
     * Retrieve secret form Vault.
     * @param key   Secret identifier
     * @return      Secret response
     */
    SecretResponse readSecret(final String key) throws VaultConnectorException;

    /**
     * List available secrets from Vault.
     * @param path  Root path to search
     * @return      List of secret keys
     */
    List<String> listSecrets(final String path) throws VaultConnectorException;

    /**
     * Write secret to Vault.
     * @param key   Secret path
     * @param value Secret value
     * @return      TRUE on success
     */
    boolean writeSecret(final String key, final String value) throws VaultConnectorException;
}
