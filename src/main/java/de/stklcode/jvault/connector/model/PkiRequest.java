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

package de.stklcode.jvault.connector.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.io.Serializable;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Collection;

/**
 * PKI request model.
 *
 * @param commonName           CN for the certificate
 * @param altNames             Subject Alternative Names
 * @param ipSans               IP Subject Alternative Names
 * @param urlSans              URI Subject Alternative Names
 * @param otherSans            custom OID/UTF8-string SANs
 * @param ttl                  Time To Live
 * @param format               Certificate format
 * @param keyFormat            Private key format
 * @param excludeCnFromSans    Exclude CN from SANs?
 * @param notAfter             Not After (expiration date)
 * @param removeRootsFromChain Remove root certificates from chain?
 * @param userIds              User IDs (OID 0.9.2342.19200300.100.1.1)
 * @param certMetadata         Base64 encoded certificate metadata
 * @author Stefan Kalscheuer
 * @since 2.0.0
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record PkiRequest(
    @JsonProperty("common_name") String commonName,
    @JsonProperty("alt_names") String altNames,
    @JsonProperty("ip_sans") String ipSans,
    @JsonProperty("url_sans") String urlSans,
    @JsonProperty("other_sans") String otherSans,
    @JsonProperty("ttl") String ttl,
    @JsonProperty("format") String format,
    @JsonProperty("private_key_format") String keyFormat,
    @JsonProperty("exclude_cn_from_sans") Boolean excludeCnFromSans,
    @JsonProperty("not_after") String notAfter,
    @JsonProperty("remove_roots_from_chain") Boolean removeRootsFromChain,
    @JsonProperty("user_ids") String userIds,
    @JsonProperty("cert_metadata") String certMetadata
) implements Serializable {

    /**
     * Construct {@link PkiRequest} object from {@link Builder}.
     *
     * @param builder Token builder.
     */
    private PkiRequest(final Builder builder) {
        this(
            builder.commonName,
            builder.altNames,
            builder.ipSans,
            builder.urlSans,
            builder.otherSans,
            builder.ttl,
            builder.format,
            builder.keyFormat,
            builder.excludeCnFromSans,
            builder.notAfter,
            builder.removeRootsFromChain,
            builder.userIds,
            builder.certMetadata
        );
    }

    /**
     * Get {@link Builder} instance.
     *
     * @return Token Builder.
     * @since 0.8
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Constants for certificate formats.
     */
    public enum Format {
        PEM("pem"),
        DER("der"),
        PEM_BUNDLE("pem_bundle");

        private final String value;

        Format(String value) {
            this.value = value;
        }

        public String value() {
            return value;
        }
    }

    /**
     * Constants for private key formats.
     */
    public enum KeyFormat {
        DER("der"),
        PKCS8("pkcs8");

        private final String value;

        KeyFormat(String value) {
            this.value = value;
        }

        public String value() {
            return value;
        }
    }


    /**
     * A builder for PKI requests.
     *
     * @author Stefan Kalscheuer
     */
    public static final class Builder {
        private String commonName;
        private String altNames;
        private String ipSans;
        private String urlSans;
        private String otherSans;
        private String ttl;
        private String format;
        private String keyFormat;
        private Boolean excludeCnFromSans;
        private String notAfter;
        private Boolean removeRootsFromChain;
        private String userIds;
        private String certMetadata;

        /**
         * Specifies the requested CN for the certificate.
         * If the CN is allowed by role policy, it will be issued. If more than one common_name is desired, specify the
         * alternative names in the {@link #} list.
         *
         * @param commonName Certificate CN
         * @return self
         */
        public Builder withCommonName(final String commonName) {
            this.commonName = commonName;
            return this;
        }

        /**
         * Specifies requested Subject Alternative Names, in a comma-delimited list.
         * These can be host names or email addresses; they will be parsed into their respective fields. If any
         * requested names do not match role policy, the entire request will be denied.
         *
         * @param altNames Alternative names, comma-delimited
         * @return self
         */
        public Builder withAltNames(final String altNames) {
            this.altNames = altNames;
            return this;
        }

        /**
         * Specifies requested Subject Alternative Names.
         * These can be host names or email addresses; they will be parsed into their respective fields. If any
         * requested names do not match role policy, the entire request will be denied.
         *
         * @param altNames Alternative names
         * @return self
         */
        public Builder withAltNames(final Collection<String> altNames) {
            if (altNames != null) {
                this.altNames = String.join(",", altNames);
            } else {
                this.altNames = null;
            }
            return this;
        }

        /**
         * Specifies requested IP Subject Alternative Names, in a comma-delimited list.
         * Only valid if the role allows IP SANs (which is the default).
         *
         * @param ipSans IP SANs, comma-delimited
         * @return self
         */
        public Builder withIpSans(final String ipSans) {
            this.ipSans = ipSans;
            return this;
        }

        /**
         * Specifies requested IP Subject Alternative Names.
         * Only valid if the role allows IP SANs (which is the default).
         *
         * @param ipSans IP SANs
         * @return self
         */
        public Builder withIpSans(final Collection<String> ipSans) {
            if (ipSans != null) {
                this.ipSans = String.join(",", ipSans);
            } else {
                this.ipSans = null;
            }

            return this;
        }

        /**
         * Specifies the requested URI Subject Alternative Names, in a comma-delimited list.
         * If any requested URIs do not match role policy, the entire request will be denied.
         *
         * @param urlSans URL SANs, comma-delimited
         * @return self
         */
        public Builder withUrlSans(final String urlSans) {
            this.urlSans = urlSans;
            return this;
        }

        /**
         * Specifies the requested URI Subject Alternative Names.
         * If any requested URIs do not match role policy, the entire request will be denied.
         *
         * @param urlSans URL SANs
         * @return self
         */
        public Builder withUrlSans(final Collection<String> urlSans) {
            if (urlSans != null) {
                this.urlSans = String.join(",", urlSans);
            } else {
                this.urlSans = null;
            }
            return this;
        }

        /**
         * Specifies custom OID/UTF8-string SANs.
         * These must match values specified on the role in "allowed_other_sans".
         * The format is the same as OpenSSL: {@code <oid>;<type>:<value>} where the only current valid type is UTF8.
         * This can be a comma-delimited list or a JSON string slice.
         *
         * @param otherSans Other SANs, comma-delimited
         * @return self
         */
        public Builder withOtherSans(final String otherSans) {
            this.otherSans = otherSans;
            return this;
        }

        /**
         * Specifies the requested URI Subject Alternative Names.
         * If any requested URIs do not match role policy, the entire request will be denied.
         *
         * @param otherSans Other SANs
         * @return self
         */
        public Builder withOtherSans(final Collection<String> otherSans) {
            if (otherSans != null) {
                this.otherSans = String.join(",", otherSans);
            } else {
                this.otherSans = null;
            }
            return this;
        }

        /**
         * Specifies requested Time To Live.
         * Cannot be greater than the role's "max_ttl" value. If not provided, the role's "ttl" value will be used.
         *
         * @param ttl Time to live
         * @return self
         */
        public Builder withTtl(final String ttl) {
            this.ttl = ttl;
            return this;
        }

        /**
         * Specifies the format for returned data.
         * Defaults to {@link Format#PEM}
         *
         * @param format Format for returned data
         * @return self
         */
        public Builder withFormat(final Format format) {
            if (format != null) {
                this.format = format.value();
            } else {
                this.format = null;
            }
            return this;
        }

        /**
         * Specifies the key format for returned data.
         * Defaults to {@link KeyFormat#DER} which returns either base64-encoded DER or PEM-encoded DER depending in
         * {@link #withFormat(Format) format}.
         *
         * @param keyFormat Key format for returned data
         * @return self
         */
        public Builder withKeyFormat(final KeyFormat keyFormat) {
            if (keyFormat != null) {
                this.keyFormat = keyFormat.value();
            } else {
                this.keyFormat = null;
            }
            return this;
        }

        /**
         * If {@code true}, the given common_name will not be included in DNS or Email Subject Alternate Names.
         * Useful if the CN is not a hostname or email address, but is instead some human-readable identifier.
         * <p>
         * Note that this does not apply to the private key within the certificate field if format
         * {@link Format#PEM_BUNDLE} parameter is specified.
         *
         * @param excludeCnFromSans Exclude common name from SANs
         * @return self
         */
        public Builder withExcludeCnFromSans(final boolean excludeCnFromSans) {
            this.excludeCnFromSans = excludeCnFromSans;
            return this;
        }

        /**
         * Set the Not After field of the certificate with specified date value.
         * The value format should be given in UTC format YYYY-MM-ddTHH:MM:SSZ.
         * Supports the Y10K end date for IEEE 802.1AR-2018 standard devices, 9999-12-31T23:59:59Z.
         *
         * @param notAfter Not after date
         * @return self
         */
        public Builder withNotAfter(final String notAfter) {
            this.notAfter = notAfter;
            return this;
        }

        /**
         * Set the Not After field of the certificate with specified date value.
         *
         * @param notAfter Not after date
         * @return self
         */
        public Builder withNotAfter(final ZonedDateTime notAfter) {
            if (notAfter != null) {
                this.notAfter = notAfter.format(DateTimeFormatter.ISO_ZONED_DATE_TIME);
            } else {
                this.notAfter = null;
            }
            return this;
        }

        /**
         * If {@code true}, the returned ca_chain field will not include any self-signed CA certificates.
         * Useful if end-users already have the root CA in their trust store.
         *
         * @param removeRootsFromChain Remove root CA certificate from CA chain
         * @return self
         */
        public Builder withRemoveRootsFromChain(final boolean removeRootsFromChain) {
            this.removeRootsFromChain = removeRootsFromChain;
            return this;
        }

        /**
         * Specifies the comma-separated list of requested User ID (OID 0.9.2342.19200300.100.1.1) Subject values to be
         * placed on the signed certificate. This field is validated against "allowed_user_ids" on the role.
         *
         * @param userIds User IDs, comma-delimited
         * @return self
         */
        public Builder withUserIds(final String userIds) {
            this.userIds = userIds;
            return this;
        }

        /**
         * Specifies the comma-separated list of requested User ID (OID 0.9.2342.19200300.100.1.1) Subject values to be
         * placed on the signed certificate. This field is validated against "allowed_user_ids" on the role.
         *
         * @param userIds Alternative names
         * @return self
         */
        public Builder withUserIds(final Collection<String> userIds) {
            if (userIds != null) {
                this.userIds = String.join(",", userIds);
            } else {
                this.userIds = null;
            }
            return this;
        }

        /**
         * A base 64 encoded value or an empty string to associate with the certificate's serial number.
         * The role's "no_store_metadata" must be set to {@code false}, otherwise an error is returned when specified.
         * <p>
         * Only available in Vault Enterprise.
         *
         * @param certMetadata Certificate metadata, base64 encoded
         * @return self
         */
        public Builder withCertMetadata(final String certMetadata) {
            this.certMetadata = certMetadata;
            return this;
        }

        /**
         * Build the token based on given parameters.
         *
         * @return the token
         */
        public PkiRequest build() {
            return new PkiRequest(this);
        }
    }
}
