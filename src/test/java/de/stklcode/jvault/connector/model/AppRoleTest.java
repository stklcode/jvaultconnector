/*
 * Copyright 2016-2024 Stefan Kalscheuer
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

import com.fasterxml.jackson.core.JsonProcessingException;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JUnit Test for {@link AppRole} and {@link AppRole.Builder}.
 *
 * @author Stefan Kalscheuer
 * @since 0.4.0
 */
class AppRoleTest extends AbstractModelTest<AppRole> {
    private static final String NAME = "TestRole";
    private static final String ID = "test-id";
    private static final Boolean BIND_SECRET_ID = true;
    private static final List<String> BOUND_CIDR_LIST = new ArrayList<>();
    private static final String CIDR_1 = "192.168.1.0/24";
    private static final String CIDR_2 = "172.16.0.0/16";
    private static final List<String> POLICIES = new ArrayList<>();
    private static final String POLICY = "policy";
    private static final String POLICY_2 = "policy2";
    private static final Integer SECRET_ID_NUM_USES = 10;
    private static final Integer SECRET_ID_TTL = 7200;
    private static final Boolean ENABLE_LOCAL_SECRET_IDS = false;
    private static final Integer TOKEN_TTL = 4800;
    private static final Integer TOKEN_MAX_TTL = 9600;
    private static final Integer TOKEN_EXPLICIT_MAX_TTL = 14400;
    private static final Boolean TOKEN_NO_DEFAULT_POLICY = false;
    private static final Integer TOKEN_NUM_USES = 42;
    private static final Integer TOKEN_PERIOD = 1234;
    private static final Token.Type TOKEN_TYPE = Token.Type.DEFAULT_SERVICE;
    private static final String JSON_MIN = "{\"role_name\":\"" + NAME + "\"}";
    private static final String JSON_FULL = String.format("{\"role_name\":\"%s\",\"role_id\":\"%s\",\"bind_secret_id\":%s,\"secret_id_bound_cidrs\":\"%s\",\"secret_id_num_uses\":%d,\"secret_id_ttl\":%d,\"enable_local_secret_ids\":%s,\"token_ttl\":%d,\"token_max_ttl\":%d,\"token_policies\":\"%s\",\"token_bound_cidrs\":\"%s\",\"token_explicit_max_ttl\":%d,\"token_no_default_policy\":%s,\"token_num_uses\":%d,\"token_period\":%d,\"token_type\":\"%s\"}",
            NAME, ID, BIND_SECRET_ID, CIDR_1, SECRET_ID_NUM_USES, SECRET_ID_TTL, ENABLE_LOCAL_SECRET_IDS, TOKEN_TTL, TOKEN_MAX_TTL, POLICY, CIDR_1, TOKEN_EXPLICIT_MAX_TTL, TOKEN_NO_DEFAULT_POLICY, TOKEN_NUM_USES, TOKEN_PERIOD, TOKEN_TYPE.value());

    AppRoleTest() {
        super(AppRole.class);
    }

    @Override
    protected AppRole createFull() {
        return AppRole.builder(NAME)
                .withId(ID)
                .withBindSecretID(BIND_SECRET_ID)
                .withSecretIdBoundCidrs(BOUND_CIDR_LIST)
                .withTokenPolicies(POLICIES)
                .withSecretIdNumUses(SECRET_ID_NUM_USES)
                .withSecretIdTtl(SECRET_ID_TTL)
                .withEnableLocalSecretIds(ENABLE_LOCAL_SECRET_IDS)
                .withTokenTtl(TOKEN_TTL)
                .withTokenMaxTtl(TOKEN_MAX_TTL)
                .withTokenBoundCidrs(BOUND_CIDR_LIST)
                .withTokenExplicitMaxTtl(TOKEN_EXPLICIT_MAX_TTL)
                .withTokenNoDefaultPolicy(TOKEN_NO_DEFAULT_POLICY)
                .withTokenNumUses(TOKEN_NUM_USES)
                .withTokenPeriod(TOKEN_PERIOD)
                .withTokenType(TOKEN_TYPE)
                .build();
    }

    @BeforeAll
    static void init() {
        BOUND_CIDR_LIST.add(CIDR_1);
        POLICIES.add(POLICY);
    }

    /**
     * Build role with only a name.
     */
    @Test
    void buildDefaultTest() throws JsonProcessingException {
        AppRole role = AppRole.builder(NAME).build();
        assertNull(role.getId());
        assertNull(role.getBindSecretId());
        assertNull(role.getSecretIdBoundCidrs());
        assertNull(role.getTokenPolicies());
        assertNull(role.getSecretIdNumUses());
        assertNull(role.getSecretIdTtl());
        assertNull(role.getEnableLocalSecretIds());
        assertNull(role.getTokenTtl());
        assertNull(role.getTokenMaxTtl());
        assertNull(role.getTokenBoundCidrs());
        assertNull(role.getTokenExplicitMaxTtl());
        assertNull(role.getTokenNoDefaultPolicy());
        assertNull(role.getTokenNumUses());
        assertNull(role.getTokenPeriod());
        assertNull(role.getTokenType());

        // Optional fields should be ignored, so JSON string should only contain role_name.
        assertEquals(JSON_MIN, objectMapper.writeValueAsString(role));
    }

    /**
     * Build token without all parameters set.
     */
    @Test
    void buildFullTest() throws JsonProcessingException {
        AppRole role = createFull();
        assertEquals(NAME, role.getName());
        assertEquals(ID, role.getId());
        assertEquals(BIND_SECRET_ID, role.getBindSecretId());
        assertEquals(BOUND_CIDR_LIST, role.getSecretIdBoundCidrs());
        assertEquals(POLICIES, role.getTokenPolicies());
        assertEquals(SECRET_ID_NUM_USES, role.getSecretIdNumUses());
        assertEquals(SECRET_ID_TTL, role.getSecretIdTtl());
        assertEquals(ENABLE_LOCAL_SECRET_IDS, role.getEnableLocalSecretIds());
        assertEquals(TOKEN_TTL, role.getTokenTtl());
        assertEquals(TOKEN_MAX_TTL, role.getTokenMaxTtl());
        assertEquals(BOUND_CIDR_LIST, role.getTokenBoundCidrs());
        assertEquals(TOKEN_EXPLICIT_MAX_TTL, role.getTokenExplicitMaxTtl());
        assertEquals(TOKEN_NO_DEFAULT_POLICY, role.getTokenNoDefaultPolicy());
        assertEquals(TOKEN_NUM_USES, role.getTokenNumUses());
        assertEquals(TOKEN_PERIOD, role.getTokenPeriod());
        assertEquals(TOKEN_TYPE.value(), role.getTokenType());

        // Verify that all parameters are included in JSON string.
        assertEquals(JSON_FULL, objectMapper.writeValueAsString(role));
    }

    /**
     * Test convenience methods
     */
    @Test
    void convenienceMethodsTest() {
        // bind_secret_id.
        AppRole role = AppRole.builder(NAME).build();
        assertNull(role.getBindSecretId());
        role = AppRole.builder(NAME).withBindSecretID().build();
        assertEquals(true, role.getBindSecretId());
        role = AppRole.builder(NAME).withoutBindSecretID().build();
        assertEquals(false, role.getBindSecretId());

        // Add single CIDR subnet.
        role = AppRole.builder(NAME).withSecretBoundCidr(CIDR_2).withTokenBoundCidr(CIDR_2).build();
        assertEquals(1, role.getSecretIdBoundCidrs().size());
        assertEquals(CIDR_2, role.getSecretIdBoundCidrs().get(0));
        assertEquals(1, role.getTokenBoundCidrs().size());
        assertEquals(CIDR_2, role.getTokenBoundCidrs().get(0));
        role = AppRole.builder(NAME)
                .withSecretIdBoundCidrs(BOUND_CIDR_LIST)
                .withSecretBoundCidr(CIDR_2)
                .withTokenBoundCidrs(BOUND_CIDR_LIST)
                .withTokenBoundCidr(CIDR_2)
                .build();
        assertEquals(2, role.getSecretIdBoundCidrs().size());
        assertTrue(role.getSecretIdBoundCidrs().containsAll(List.of(CIDR_1, CIDR_2)));
        assertEquals(2, role.getTokenBoundCidrs().size());
        assertTrue(role.getSecretIdBoundCidrs().containsAll(List.of(CIDR_1, CIDR_2)));

        // Add single policy.
        role = AppRole.builder(NAME).withTokenPolicy(POLICY_2).build();
        assertEquals(1, role.getTokenPolicies().size());
        assertEquals(POLICY_2, role.getTokenPolicies().get(0));
        role = AppRole.builder(NAME)
                .withTokenPolicies(POLICIES)
                .withTokenPolicy(POLICY_2)
                .build();
        assertEquals(2, role.getTokenPolicies().size());
        assertTrue(role.getTokenPolicies().containsAll(List.of(POLICY, POLICY_2)));
    }
}
