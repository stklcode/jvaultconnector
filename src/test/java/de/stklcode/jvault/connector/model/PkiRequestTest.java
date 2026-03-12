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

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JUnit Test for {@link PkiRequest} model.
 *
 * @author Stefan Kalscheuer
 */
class PkiRequestTest extends AbstractModelTest<PkiRequest> {

    private static final String COMMON_NAME = "test.example.com";
    private static final List<String> ALT_NAMES = List.of("www.example.com", "test.example.com");
    private static final String ALT_NAMES_STRING = "www.example.com,test.example.com";
    private static final List<String> IP_SANS = List.of("192.168.1.1", "10.0.0.5");
    private static final String IP_SANS_STRING = "192.168.1.1,10.0.0.5";
    private static final List<String> URL_SANS = List.of("https://api.example.com/v1");
    private static final String URL_SANS_STRING = "https://api.example.com/v1";
    private static final List<String> OTHER_SANS = List.of("DNS:dns.example.com", "email:mail@example.com");
    private static final String OTHER_SANS_STRING = "DNS:dns.example.com,email:mail@example.com";
    private static final String TTL = "3600"; // 1 hour
    private static final PkiRequest.Format FORMAT = PkiRequest.Format.PEM_BUNDLE;
    private static final PkiRequest.KeyFormat KEY_FORMAT = PkiRequest.KeyFormat.PKCS8;
    private static final boolean EXCLUDE_CN_FROM_SANS = true;
    private static final String NOT_AFTER_DATE = "2030-12-31T23:59:59Z";
    private static final boolean REMOVE_ROOTS_FROM_CHAIN = true;
    private static final List<String> USER_IDS = List.of("user-role","group-admin");
    private static final String USER_IDS_STRING = "user-role,group-admin";
    private static final String CERT_METADATA = "dGVzdCBtZXRhZGF0YQ==";

    PkiRequestTest() {
        super(PkiRequest.class);
    }

    @Override
    protected PkiRequest createFull() {
        return PkiRequest.builder()
            .withCommonName(COMMON_NAME)
            .withAltNames(ALT_NAMES)
            .withIpSans(IP_SANS)
            .withUrlSans(URL_SANS)
            .withOtherSans(OTHER_SANS)
            .withTtl(TTL)
            .withFormat(FORMAT)
            .withKeyFormat(KEY_FORMAT)
            .withExcludeCnFromSans(EXCLUDE_CN_FROM_SANS)
            .withNotAfter(NOT_AFTER_DATE)
            .withRemoveRootsFromChain(REMOVE_ROOTS_FROM_CHAIN)
            .withUserIds(USER_IDS)
            .withCertMetadata(CERT_METADATA)
            .build();
    }

    @Test
    void buildFullTest() {
        PkiRequest request = createFull();

        assertEquals(COMMON_NAME, request.commonName(), "commonName mismatch");
        assertEquals(ALT_NAMES_STRING, request.altNames(), "altNames mismatch");
        assertEquals(IP_SANS_STRING, request.ipSans(), "ipSans mismatch");
        assertEquals(URL_SANS_STRING, request.urlSans(), "urlSans mismatch");
        assertEquals(OTHER_SANS_STRING, request.otherSans(), "otherSans mismatch");
        assertEquals(TTL, request.ttl(), "ttl mismatch");
        assertEquals(PkiRequest.Format.PEM_BUNDLE.value(), request.format(), "format mismatch");
        assertEquals(PkiRequest.KeyFormat.PKCS8.value(), request.keyFormat(), "keyFormat mismatch");
        assertEquals(EXCLUDE_CN_FROM_SANS, request.excludeCnFromSans(), "excludeCnFromSans mismatch");
        assertEquals(NOT_AFTER_DATE, request.notAfter(), "notAfter mismatch");
        assertEquals(REMOVE_ROOTS_FROM_CHAIN, request.removeRootsFromChain(), "removeRootsFromChain mismatch");
        assertEquals(USER_IDS_STRING, request.userIds(), "userIds mismatch");
        assertEquals(CERT_METADATA, request.certMetadata(), "certMetadata mismatch");

        assertEquals(
            "{" +
                "\"common_name\":\"" + COMMON_NAME + "\"," +
                "\"alt_names\":\"" + ALT_NAMES_STRING + "\"," +
                "\"ip_sans\":\"" + IP_SANS_STRING + "\"," +
                "\"url_sans\":\"" + URL_SANS_STRING + "\"," +
                "\"other_sans\":\"" + OTHER_SANS_STRING + "\"," +
                "\"ttl\":\"" + TTL + "\"," +
                "\"format\":\"" + FORMAT.value() + "\"," +
                "\"private_key_format\":\"" + KEY_FORMAT.value() + "\"," +
                "\"exclude_cn_from_sans\":" + EXCLUDE_CN_FROM_SANS + "," +
                "\"not_after\":\"" + NOT_AFTER_DATE  + "\"," +
                "\"remove_roots_from_chain\":" + REMOVE_ROOTS_FROM_CHAIN + "," +
                "\"user_ids\":\"" + USER_IDS_STRING + "\"," +
                "\"cert_metadata\":\"" + CERT_METADATA + "\"" +
                "}",
            objectMapper.writeValueAsString(request),
            "unexpected JSON output for full request"
        );
    }

    @Test
    void buildFullStringsTest() {
        PkiRequest request = PkiRequest.builder()
            .withCommonName(COMMON_NAME)
            .withAltNames(ALT_NAMES_STRING)
            .withIpSans(IP_SANS_STRING)
            .withUrlSans(URL_SANS_STRING)
            .withOtherSans(OTHER_SANS_STRING)
            .withTtl(TTL)
            .withFormat(FORMAT)
            .withKeyFormat(KEY_FORMAT)
            .withExcludeCnFromSans(EXCLUDE_CN_FROM_SANS)
            .withNotAfter(NOT_AFTER_DATE)
            .withRemoveRootsFromChain(REMOVE_ROOTS_FROM_CHAIN)
            .withUserIds(USER_IDS_STRING)
            .withCertMetadata(CERT_METADATA)
            .build();

        assertEquals(COMMON_NAME, request.commonName(), "commonName mismatch");
        assertEquals(ALT_NAMES_STRING, request.altNames(), "altNames mismatch");
        assertEquals(IP_SANS_STRING, request.ipSans(), "ipSans mismatch");
        assertEquals(URL_SANS_STRING, request.urlSans(), "urlSans mismatch");
        assertEquals(OTHER_SANS_STRING, request.otherSans(), "otherSans mismatch");
        assertEquals(TTL, request.ttl(), "ttl mismatch");
        assertEquals(PkiRequest.Format.PEM_BUNDLE.value(), request.format(), "format mismatch");
        assertEquals(PkiRequest.KeyFormat.PKCS8.value(), request.keyFormat(), "keyFormat mismatch");
        assertEquals(EXCLUDE_CN_FROM_SANS, request.excludeCnFromSans(), "excludeCnFromSans mismatch");
        assertEquals(NOT_AFTER_DATE, request.notAfter(), "notAfter mismatch");
        assertEquals(REMOVE_ROOTS_FROM_CHAIN, request.removeRootsFromChain(), "removeRootsFromChain mismatch");
        assertEquals(USER_IDS_STRING, request.userIds(), "userIds mismatch");
        assertEquals(CERT_METADATA, request.certMetadata(), "certMetadata mismatch");

        assertEquals(
            "{" +
                "\"common_name\":\"" + COMMON_NAME + "\"," +
                "\"alt_names\":\"" + ALT_NAMES_STRING + "\"," +
                "\"ip_sans\":\"" + IP_SANS_STRING + "\"," +
                "\"url_sans\":\"" + URL_SANS_STRING + "\"," +
                "\"other_sans\":\"" + OTHER_SANS_STRING + "\"," +
                "\"ttl\":\"" + TTL + "\"," +
                "\"format\":\"" + FORMAT.value() + "\"," +
                "\"private_key_format\":\"" + KEY_FORMAT.value() + "\"," +
                "\"exclude_cn_from_sans\":" + EXCLUDE_CN_FROM_SANS + "," +
                "\"not_after\":\"" + NOT_AFTER_DATE  + "\"," +
                "\"remove_roots_from_chain\":" + REMOVE_ROOTS_FROM_CHAIN + "," +
                "\"user_ids\":\"" + USER_IDS_STRING + "\"," +
                "\"cert_metadata\":\"" + CERT_METADATA + "\"" +
                "}",
            objectMapper.writeValueAsString(request),
            "unexpected JSON output for full request"
        );
    }

    @Test
    void buildMinimalTest() {
        PkiRequest request = PkiRequest.builder()
            .withCommonName(COMMON_NAME)
            .build();

        assertEquals(COMMON_NAME, request.commonName(), "commonName mismatch");
        assertNull(request.altNames(), "unexpected altNames");
        assertNull( request.ipSans(), "unexpected ipSans");
        assertNull(request.urlSans(), "unexpected urlSans");
        assertNull(request.otherSans(), "unexpected otherSans");
        assertNull(request.ttl(), "unexpected ttl");
        assertNull(request.format(), "unexpected format");
        assertNull(request.keyFormat(), "unexpected keyFormat");
        assertNull(request.excludeCnFromSans(), "unexpected excludeCnFromSans");
        assertNull(request.notAfter(), "unexpected notAfter");
        assertNull(request.removeRootsFromChain(), "unexpected removeRootsFromChain");
        assertNull(request.userIds(), "unexpected userIds");
        assertNull(request.certMetadata(), "unexpected certMetadata");

        assertEquals(
            "{\"common_name\":\"" + COMMON_NAME + "\"}",
            objectMapper.writeValueAsString(request),
            "unexpected JSON output for minimal request"
        );
    }
}
