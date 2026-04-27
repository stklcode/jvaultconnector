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
    private static final Long SECRET_ID_TTL = 7200L;
    private static final Boolean LOCAL_SECRET_IDS = false;
    private static final Long TOKEN_TTL = 4800L;
    private static final Long TOKEN_MAX_TTL = 9600L;
    private static final Long TOKEN_EXPLICIT_MAX_TTL = 14400L;
    private static final Boolean TOKEN_NO_DEFAULT_POLICY = false;
    private static final Integer TOKEN_NUM_USES = 42;
    private static final Integer TOKEN_PERIOD = 1234;
    private static final Token.Type TOKEN_TYPE = Token.Type.DEFAULT_SERVICE;
    private static final String JSON_MIN = "{\"role_name\":\"" + NAME + "\"}";
    private static final String JSON_FULL = String.format("{\"role_name\":\"%s\",\"role_id\":\"%s\",\"bind_secret_id\":%s,\"secret_id_bound_cidrs\":\"%s\",\"secret_id_num_uses\":%d,\"secret_id_ttl\":%d,\"local_secret_ids\":%s,\"token_ttl\":%d,\"token_max_ttl\":%d,\"token_policies\":\"%s\",\"token_bound_cidrs\":\"%s\",\"token_explicit_max_ttl\":%d,\"token_no_default_policy\":%s,\"token_num_uses\":%d,\"token_period\":%d,\"token_type\":\"%s\"}",
        NAME, ID, BIND_SECRET_ID, CIDR_1, SECRET_ID_NUM_USES, SECRET_ID_TTL, LOCAL_SECRET_IDS, TOKEN_TTL, TOKEN_MAX_TTL, POLICY, CIDR_1, TOKEN_EXPLICIT_MAX_TTL, TOKEN_NO_DEFAULT_POLICY, TOKEN_NUM_USES, TOKEN_PERIOD, TOKEN_TYPE.value());

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
            .withLocalSecretIds(LOCAL_SECRET_IDS)
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
    void buildDefaultTest() {
        AppRole role = AppRole.builder(NAME).build();
        assertNull(role.id());
        assertNull(role.bindSecretId());
        assertNull(role.secretIdBoundCidrs());
        assertNull(role.tokenPolicies());
        assertNull(role.secretIdNumUses());
        assertNull(role.secretIdTtl());
        assertNull(role.localSecretIds());
        assertNull(role.tokenTtl());
        assertNull(role.tokenMaxTtl());
        assertNull(role.tokenBoundCidrs());
        assertNull(role.tokenExplicitMaxTtl());
        assertNull(role.tokenNoDefaultPolicy());
        assertNull(role.tokenNumUses());
        assertNull(role.tokenPeriod());
        assertNull(role.tokenType());

        // Optional fields should be ignored, so JSON string should only contain role_name.
        assertEquals(JSON_MIN, objectMapper.writeValueAsString(role));
    }

    /**
     * Build token without all parameters set.
     */
    @Test
    void buildFullTest() {
        AppRole role = createFull();
        assertEquals(NAME, role.name());
        assertEquals(ID, role.id());
        assertEquals(BIND_SECRET_ID, role.bindSecretId());
        assertEquals(BOUND_CIDR_LIST, role.secretIdBoundCidrs());
        assertEquals(POLICIES, role.tokenPolicies());
        assertEquals(SECRET_ID_NUM_USES, role.secretIdNumUses());
        assertEquals(SECRET_ID_TTL, role.secretIdTtl());
        assertEquals(LOCAL_SECRET_IDS, role.localSecretIds());
        assertEquals(TOKEN_TTL, role.tokenTtl());
        assertEquals(TOKEN_MAX_TTL, role.tokenMaxTtl());
        assertEquals(BOUND_CIDR_LIST, role.tokenBoundCidrs());
        assertEquals(TOKEN_EXPLICIT_MAX_TTL, role.tokenExplicitMaxTtl());
        assertEquals(TOKEN_NO_DEFAULT_POLICY, role.tokenNoDefaultPolicy());
        assertEquals(TOKEN_NUM_USES, role.tokenNumUses());
        assertEquals(TOKEN_PERIOD, role.tokenPeriod());
        assertEquals(TOKEN_TYPE.value(), role.tokenType());

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
        assertNull(role.bindSecretId());
        role = AppRole.builder(NAME).withBindSecretID().build();
        assertEquals(true, role.bindSecretId());
        role = AppRole.builder(NAME).withoutBindSecretID().build();
        assertEquals(false, role.bindSecretId());

        // Add single CIDR subnet.
        role = AppRole.builder(NAME).withSecretBoundCidr(CIDR_2).withTokenBoundCidr(CIDR_2).build();
        assertEquals(1, role.secretIdBoundCidrs().size());
        assertEquals(CIDR_2, role.secretIdBoundCidrs().get(0));
        assertEquals(1, role.tokenBoundCidrs().size());
        assertEquals(CIDR_2, role.tokenBoundCidrs().get(0));
        role = AppRole.builder(NAME)
            .withSecretIdBoundCidrs(BOUND_CIDR_LIST)
            .withSecretBoundCidr(CIDR_2)
            .withTokenBoundCidrs(BOUND_CIDR_LIST)
            .withTokenBoundCidr(CIDR_2)
            .build();
        assertEquals(2, role.secretIdBoundCidrs().size());
        assertTrue(role.secretIdBoundCidrs().containsAll(List.of(CIDR_1, CIDR_2)));
        assertEquals(2, role.tokenBoundCidrs().size());
        assertTrue(role.secretIdBoundCidrs().containsAll(List.of(CIDR_1, CIDR_2)));

        // Add single policy.
        role = AppRole.builder(NAME).withTokenPolicy(POLICY_2).build();
        assertEquals(1, role.tokenPolicies().size());
        assertEquals(POLICY_2, role.tokenPolicies().get(0));
        role = AppRole.builder(NAME)
            .withTokenPolicies(POLICIES)
            .withTokenPolicy(POLICY_2)
            .build();
        assertEquals(2, role.tokenPolicies().size());
        assertTrue(role.tokenPolicies().containsAll(List.of(POLICY, POLICY_2)));
    }
}
