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

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JUnit Test for {@link Token} and {@link Token.Builder}.
 *
 * @author Stefan Kalscheuer
 * @since 0.4.0
 */
class TokenTest extends AbstractModelTest<Token> {
    private static final String ID = "test-id";
    private static final String DISPLAY_NAME = "display-name";
    private static final Boolean NO_PARENT = false;
    private static final Boolean NO_DEFAULT_POLICY = false;
    private static final Long TTL = 123L;
    private static final Long EXPLICIT_MAX_TTL = 456L;
    private static final Integer NUM_USES = 4;
    private static final List<String> POLICIES = new ArrayList<>();
    private static final String POLICY = "policy";
    private static final String POLICY_2 = "policy2";
    private static final String POLICY_3 = "policy3";
    private static final Map<String, String> META = new HashMap<>();
    private static final String META_KEY = "key";
    private static final String META_VALUE = "value";
    private static final String META_KEY_2 = "key2";
    private static final String META_VALUE_2 = "value2";
    private static final Boolean RENEWABLE = true;
    private static final Integer PERIOD = 3600;
    private static final String ENTITY_ALIAS = "alias-value";
    private static final String JSON_FULL = "{\"id\":\"test-id\",\"type\":\"service\",\"display_name\":\"display-name\",\"no_parent\":false,\"no_default_policy\":false,\"ttl\":123,\"explicit_max_ttl\":456,\"num_uses\":4,\"policies\":[\"policy\"],\"meta\":{\"key\":\"value\"},\"renewable\":true,\"period\":3600,\"entity_alias\":\"alias-value\"}";

    TokenTest() {
        super(Token.class);
    }

    @Override
    protected Token createFull() {
        return Token.builder()
            .withId(ID)
            .withType(Token.Type.SERVICE)
            .withDisplayName(DISPLAY_NAME)
            .withNoParent(NO_PARENT)
            .withNoDefaultPolicy(NO_DEFAULT_POLICY)
            .withTtl(TTL)
            .withExplicitMaxTtl(EXPLICIT_MAX_TTL)
            .withNumUses(NUM_USES)
            .withPolicies(POLICIES)
            .withMeta(META)
            .withRenewable(RENEWABLE)
            .withPeriod(PERIOD)
            .withEntityAlias(ENTITY_ALIAS)
            .build();
    }

    @BeforeAll
    static void init() {
        POLICIES.add(POLICY);
        META.put(META_KEY, META_VALUE);
    }

    /**
     * Build token without any parameters.
     */
    @Test
    void buildDefaultTest() {
        Token token = Token.builder().build();
        assertNull(token.id());
        assertNull(token.type());
        assertNull(token.displayName());
        assertNull(token.noParent());
        assertNull(token.noDefaultPolicy());
        assertNull(token.ttl());
        assertNull(token.explicitMaxTtl());
        assertNull(token.numUses());
        assertNull(token.policies());
        assertNull(token.meta());
        assertNull(token.renewable());
        assertNull(token.period());
        assertNull(token.entityAlias());

        // Optional fields should be ignored, so JSON string should be empty.
        assertEquals("{}", objectMapper.writeValueAsString(token));
    }

    /**
     * Build token without all parameters set.
     */
    @Test
    void buildFullTest() {
        Token token = createFull();
        assertEquals(ID, token.id());
        assertEquals(Token.Type.SERVICE.value(), token.type());
        assertEquals(DISPLAY_NAME, token.displayName());
        assertEquals(NO_PARENT, token.noParent());
        assertEquals(NO_DEFAULT_POLICY, token.noDefaultPolicy());
        assertEquals(TTL, token.ttl());
        assertEquals(EXPLICIT_MAX_TTL, token.explicitMaxTtl());
        assertEquals(NUM_USES, token.numUses());
        assertEquals(POLICIES, token.policies());
        assertEquals(META, token.meta());
        assertEquals(RENEWABLE, token.renewable());
        assertEquals(PERIOD, token.period());

        // Verify that all parameters are included in JSON string.
        assertEquals(JSON_FULL, objectMapper.writeValueAsString(token));
    }

    /**
     * Test convenience methods
     */
    @Test
    void convenienceMethodsTest() {
        // Parent.
        Token token = Token.builder().asOrphan().build();
        assertEquals(true, token.noParent());
        token = Token.builder().withParent().build();
        assertEquals(false, token.noParent());

        // Default policy.
        token = Token.builder().withDefaultPolicy().build();
        assertEquals(false, token.noDefaultPolicy());
        token = Token.builder().withoutDefaultPolicy().build();
        assertEquals(true, token.noDefaultPolicy());

        // Renewability.
        token = Token.builder().renewable().build();
        assertEquals(true, token.renewable());
        token = Token.builder().notRenewable().build();
        assertEquals(false, token.renewable());

        // Add single policy.
        token = Token.builder().withPolicy(POLICY_2).build();
        assertEquals(1, token.policies().size());
        assertEquals(List.of(POLICY_2), token.policies());
        token = Token.builder()
            .withPolicies(POLICY, POLICY_2)
            .withPolicy(POLICY_3)
            .build();
        assertEquals(3, token.policies().size());
        assertTrue(token.policies().containsAll(List.of(POLICY, POLICY_2, POLICY_3)));

        // Add single metadata.
        token = Token.builder().withMeta(META_KEY_2, META_VALUE_2).build();
        assertEquals(1, token.meta().size());
        assertEquals(Set.of(META_KEY_2), token.meta().keySet());
        assertEquals(META_VALUE_2, token.meta().get(META_KEY_2));
        token = Token.builder()
            .withMeta(META)
            .withMeta(META_KEY_2, META_VALUE_2)
            .build();
        assertEquals(2, token.meta().size());
        assertEquals(META_VALUE, token.meta().get(META_KEY));
        assertEquals(META_VALUE_2, token.meta().get(META_KEY_2));
    }
}
