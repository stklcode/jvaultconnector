package de.stklcode.jvault.connector.internal;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import de.stklcode.jvault.connector.exception.*;
import de.stklcode.jvault.connector.model.response.ErrorResponse;
import org.apache.http.HttpResponse;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.*;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.*;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Helper class to bundle Vault HTTP requests.
 *
 * @author Stefan Kalscheuer
 * @since 0.8 Extracted methods from {@link de.stklcode.jvault.connector.HTTPVaultConnector}.
 */
public final class RequestHelper implements Serializable {
    private static final String HEADER_VAULT_TOKEN = "X-Vault-Token";

    private final String baseURL;                   // Base URL of Vault.
    private final Integer timeout;                  // Timeout in milliseconds.
    private final int retries;                      // Number of retries on 5xx errors.
    private final String tlsVersion;                // TLS version (#22).
    private final X509Certificate trustedCaCert;    // Trusted CA certificate.
    private final ObjectMapper jsonMapper;

    /**
     * Constructor of the request helper.
     *
     * @param baseURL       The URL
     * @param retries       Number of retries on 5xx errors
     * @param timeout       Timeout for HTTP requests (milliseconds)
     * @param tlsVersion    TLS Version.
     * @param trustedCaCert Trusted CA certificate
     */
    public RequestHelper(final String baseURL,
                         final int retries,
                         final Integer timeout,
                         final String tlsVersion,
                         final X509Certificate trustedCaCert) {
        this.baseURL = baseURL;
        this.retries = retries;
        this.timeout = timeout;
        this.tlsVersion = tlsVersion;
        this.trustedCaCert = trustedCaCert;
        this.jsonMapper = new ObjectMapper();
    }

    /**
     * Execute HTTP request using POST method.
     *
     * @param path    URL path (relative to base).
     * @param payload Map of payload values (will be converted to JSON).
     * @param token   Vault token (may be {@code null}).
     * @return HTTP response
     * @throws VaultConnectorException on connection error
     * @since 0.8 Added {@code token} parameter.
     */
    public String post(final String path, final Object payload, final String token) throws VaultConnectorException {
        /* Initialize post */
        HttpPost post = new HttpPost(baseURL + path);

        /* generate JSON from payload */
        StringEntity input;
        try {
            input = new StringEntity(jsonMapper.writeValueAsString(payload), StandardCharsets.UTF_8);
        } catch (JsonProcessingException e) {
            throw new InvalidRequestException(Error.PARSE_RESPONSE, e);
        }
        input.setContentEncoding("UTF-8");
        input.setContentType("application/json");
        post.setEntity(input);

        /* Set X-Vault-Token header */
        if (token != null) {
            post.addHeader(HEADER_VAULT_TOKEN, token);
        }

        return request(post, retries);
    }

    /**
     * Execute HTTP request using POST method and parse JSON result.
     *
     * @param path    URL path (relative to base).
     * @param payload Map of payload values (will be converted to JSON).
     * @param token   Vault token (may be {@code null}).
     * @param target  Target class.
     * @param <T>     Target type.
     * @return HTTP response
     * @throws VaultConnectorException on connection error
     * @since 0.8
     */
    public <T> T post(final String path, final Object payload, final String token, final Class<T> target)
            throws VaultConnectorException {
        try {
            String response = post(path, payload, token);
            return jsonMapper.readValue(response, target);
        } catch (IOException e) {
            throw new InvalidResponseException(Error.PARSE_RESPONSE, e);
        }
    }

    /**
     * Execute HTTP request using POST method and expect empty (204) response.
     *
     * @param path    URL path (relative to base).
     * @param payload Map of payload values (will be converted to JSON).
     * @param token   Vault token (may be {@code null}).
     * @throws VaultConnectorException on connection error
     * @since 0.8
     */
    public void postWithoutResponse(final String path, final Object payload, final String token) throws VaultConnectorException {
        if (!post(path, payload, token).isEmpty()) {
            throw new InvalidResponseException(Error.UNEXPECTED_RESPONSE);
        }
    }

    /**
     * Execute HTTP request using PUT method.
     *
     * @param path    URL path (relative to base).
     * @param payload Map of payload values (will be converted to JSON).
     * @param token   Vault token (may be {@code null}).
     * @return HTTP response
     * @throws VaultConnectorException on connection error
     * @since 0.8 Added {@code token} parameter.
     */
    public String put(final String path, final Map<String, String> payload, final String token) throws VaultConnectorException {
        /* Initialize put */
        HttpPut put = new HttpPut(baseURL + path);

        /* generate JSON from payload */
        StringEntity entity = null;
        try {
            entity = new StringEntity(jsonMapper.writeValueAsString(payload));
        } catch (UnsupportedEncodingException | JsonProcessingException e) {
            throw new InvalidRequestException("Payload serialization failed", e);
        }

        /* Parse parameters */
        put.setEntity(entity);

        /* Set X-Vault-Token header */
        if (token != null) {
            put.addHeader(HEADER_VAULT_TOKEN, token);
        }

        return request(put, retries);
    }

    /**
     * Execute HTTP request using PUT method and parse JSON result.
     *
     * @param path    URL path (relative to base).
     * @param payload Map of payload values (will be converted to JSON).
     * @param token   Vault token (may be {@code null}).
     * @param target  Target class.
     * @param <T>     Target type.
     * @return HTTP response
     * @throws VaultConnectorException on connection error
     * @since 0.8
     */
    public <T> T put(final String path, final Map<String, String> payload, final String token, final Class<T> target)
            throws VaultConnectorException {
        try {
            String response = put(path, payload, token);
            return jsonMapper.readValue(response, target);
        } catch (IOException e) {
            throw new InvalidResponseException(Error.PARSE_RESPONSE, e);
        }
    }

    /**
     * Execute HTTP request using PUT method and expect empty (204) response.
     *
     * @param path    URL path (relative to base).
     * @param payload Map of payload values (will be converted to JSON).
     * @param token   Vault token (may be {@code null}).
     * @throws VaultConnectorException on connection error
     * @since 0.8
     */
    public void putWithoutResponse(final String path, final Map<String, String> payload, final String token)
            throws VaultConnectorException {
        if (!put(path, payload, token).isEmpty()) {
            throw new InvalidResponseException(Error.UNEXPECTED_RESPONSE);
        }
    }

    /**
     * Execute HTTP request using DELETE method.
     *
     * @param path  URL path (relative to base).
     * @param token Vault token (may be {@code null}).
     * @return HTTP response
     * @throws VaultConnectorException on connection error
     * @since 0.8 Added {@code token} parameter.
     */
    public String delete(final String path, final String token) throws VaultConnectorException {
        /* Initialize delete */
        HttpDelete delete = new HttpDelete(baseURL + path);

        /* Set X-Vault-Token header */
        if (token != null) {
            delete.addHeader(HEADER_VAULT_TOKEN, token);
        }

        return request(delete, retries);
    }

    /**
     * Execute HTTP request using DELETE method and expect empty (204) response.
     *
     * @param path  URL path (relative to base).
     * @param token Vault token (may be {@code null}).
     * @throws VaultConnectorException on connection error
     * @since 0.8
     */
    public void deleteWithoutResponse(final String path, final String token) throws VaultConnectorException {
        if (!delete(path, token).isEmpty()) {
            throw new InvalidResponseException(Error.UNEXPECTED_RESPONSE);
        }
    }

    /**
     * Execute HTTP request using GET method.
     *
     * @param path    URL path (relative to base).
     * @param payload Map of payload values (will be converted to JSON).
     * @param token   Vault token (may be {@code null}).
     * @return HTTP response
     * @throws VaultConnectorException on connection error
     * @since 0.8 Added {@code token} parameter.
     */
    public String get(final String path, final Map<String, String> payload, final String token)
            throws VaultConnectorException {
        HttpGet get;
        try {
            /* Add parameters to URI */
            URIBuilder uriBuilder = new URIBuilder(baseURL + path);
            payload.forEach(uriBuilder::addParameter);

            /* Initialize request */
            get = new HttpGet(uriBuilder.build());
        } catch (URISyntaxException e) {
            /* this should never occur and may leak sensible information */
            throw new InvalidRequestException(Error.URI_FORMAT);
        }

        /* Set X-Vault-Token header */
        if (token != null) {
            get.addHeader(HEADER_VAULT_TOKEN, token);
        }

        return request(get, retries);
    }

    /**
     * Execute HTTP request using GET method and parse JSON result to target class.
     *
     * @param path    URL path (relative to base).
     * @param payload Map of payload values (will be converted to JSON).
     * @param token   Vault token (may be {@code null}).
     * @param target  Target class.
     * @param <T>     Target type.
     * @return HTTP response
     * @throws VaultConnectorException on connection error
     * @since 0.8
     */
    public <T> T get(final String path, final Map<String, String> payload, final String token, final Class<T> target)
            throws VaultConnectorException {
        try {
            String response = get(path, payload, token);
            return jsonMapper.readValue(response, target);
        } catch (IOException e) {
            throw new InvalidResponseException(Error.PARSE_RESPONSE, e);
        }
    }

    /**
     * Execute prepared HTTP request and return result.
     *
     * @param base    Prepares Request
     * @param retries number of retries
     * @return HTTP response
     * @throws VaultConnectorException on connection error
     */
    private String request(final HttpRequestBase base, final int retries) throws VaultConnectorException {
        /* Set JSON Header */
        base.addHeader("accept", "application/json");

        CloseableHttpResponse response = null;

        try (CloseableHttpClient httpClient = HttpClientBuilder.create()
                .setSSLSocketFactory(createSSLSocketFactory())
                .build()) {
            /* Set custom timeout, if defined */
            if (this.timeout != null) {
                base.setConfig(RequestConfig.copy(RequestConfig.DEFAULT).setConnectTimeout(timeout).build());
            }

            /* Execute request */
            response = httpClient.execute(base);

            /* Check if response is valid */
            if (response == null) {
                throw new InvalidResponseException("Response unavailable");
            }

            switch (response.getStatusLine().getStatusCode()) {
                case 200:
                    return handleResult(response);
                case 204:
                    return "";
                case 403:
                    throw new PermissionDeniedException();
                default:
                    if (response.getStatusLine().getStatusCode() >= 500
                            && response.getStatusLine().getStatusCode() < 600 && retries > 0) {
                        /* Retry on 5xx errors */
                        return request(base, retries - 1);
                    } else {
                        /* Fail on different error code and/or no retries left */
                        handleError(response);

                        /* Throw exception without details, if response entity is empty. */
                        throw new InvalidResponseException(Error.RESPONSE_CODE,
                                response.getStatusLine().getStatusCode());
                    }
            }
        } catch (IOException e) {
            throw new InvalidResponseException(Error.READ_RESPONSE, e);
        } finally {
            if (response != null && response.getEntity() != null) {
                try {
                    EntityUtils.consume(response.getEntity());
                } catch (IOException ignored) {
                    // Exception ignored.
                }
            }
        }
    }

    /**
     * Create a custom socket factory from trusted CA certificate.
     *
     * @return The factory.
     * @throws TlsException An error occurred during initialization of the SSL context.
     * @since 0.8.0
     */
    private SSLConnectionSocketFactory createSSLSocketFactory() throws TlsException {
        try {
            // Create context..
            SSLContext context = SSLContext.getInstance(tlsVersion);

            if (trustedCaCert != null) {
                // Create Keystore with trusted certificate.
                KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                keyStore.load(null, null);
                keyStore.setCertificateEntry("trustedCert", trustedCaCert);

                // Initialize TrustManager.
                TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                tmf.init(keyStore);
                context.init(null, tmf.getTrustManagers(), null);
            } else {
                context.init(null, null, null);
            }

            return new SSLConnectionSocketFactory(
                    context,
                    null,
                    null,
                    SSLConnectionSocketFactory.getDefaultHostnameVerifier()
            );
        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException | KeyManagementException e) {
            throw new TlsException(Error.INIT_SSL_CONTEXT, e);
        }
    }

    /**
     * Handle successful result.
     *
     * @param response The raw HTTP response (assuming status code 200)
     * @return Complete response body as String
     * @throws InvalidResponseException on reading errors
     */
    private String handleResult(final HttpResponse response) throws InvalidResponseException {
        try (BufferedReader br = new BufferedReader(
                new InputStreamReader(response.getEntity().getContent()))) {
            return br.lines().collect(Collectors.joining("\n"));
        } catch (IOException ignored) {
            throw new InvalidResponseException(Error.READ_RESPONSE, 200);
        }
    }

    /**
     * Handle unsuccessful response. Throw detailed exception if possible.
     *
     * @param response The raw HTTP response (assuming status code 5xx)
     * @throws VaultConnectorException Expected exception with details to throw
     */
    private void handleError(final HttpResponse response) throws VaultConnectorException {
        if (response.getEntity() != null) {
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(response.getEntity().getContent()))) {
                String responseString = br.lines().collect(Collectors.joining("\n"));
                ErrorResponse er = jsonMapper.readValue(responseString, ErrorResponse.class);
                /* Check for "permission denied" response */
                if (!er.getErrors().isEmpty() && er.getErrors().get(0).equals("permission denied")) {
                    throw new PermissionDeniedException();
                }
                throw new InvalidResponseException(Error.RESPONSE_CODE,
                        response.getStatusLine().getStatusCode(), er.toString());
            } catch (IOException ignored) {
                // Exception ignored.
            }
        }
    }
}
