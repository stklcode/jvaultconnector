/*
 * Copyright 2016-2021 Stefan Kalscheuer
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
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

/**
 * JUnit Test for {@link AppRole} and {@link AppRole.Builder}.
 *
 * @author Stefan Kalscheuer
 * @since 0.4.0
 */
class AppRoleTest {
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
        assertThat(role.getId(), is(nullValue()));
        assertThat(role.getBindSecretId(), is(nullValue()));
        assertThat(role.getSecretIdBoundCidrs(), is(nullValue()));
        assertThat(role.getTokenPolicies(), is(nullValue()));
        assertThat(role.getSecretIdNumUses(), is(nullValue()));
        assertThat(role.getSecretIdTtl(), is(nullValue()));
        assertThat(role.getEnableLocalSecretIds(), is(nullValue()));
        assertThat(role.getTokenTtl(), is(nullValue()));
        assertThat(role.getTokenMaxTtl(), is(nullValue()));
        assertThat(role.getTokenBoundCidrs(), is(nullValue()));
        assertThat(role.getTokenExplicitMaxTtl(), is(nullValue()));
        assertThat(role.getTokenNoDefaultPolicy(), is(nullValue()));
        assertThat(role.getTokenNumUses(), is(nullValue()));
        assertThat(role.getTokenPeriod(), is(nullValue()));
        assertThat(role.getTokenType(), is(nullValue()));

        /* optional fields should be ignored, so JSON string should only contain role_name */
        assertThat(new ObjectMapper().writeValueAsString(role), is(JSON_MIN));
    }

    /**
     * Build token without all parameters set.
     */
    @Test
    void buildFullTest() throws JsonProcessingException {
        AppRole role = AppRole.builder(NAME)
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
        assertThat(role.getName(), is(NAME));
        assertThat(role.getId(), is(ID));
        assertThat(role.getBindSecretId(), is(BIND_SECRET_ID));
        assertThat(role.getSecretIdBoundCidrs(), is(BOUND_CIDR_LIST));
        assertThat(role.getTokenPolicies(), is(POLICIES));
        assertThat(role.getSecretIdNumUses(), is(SECRET_ID_NUM_USES));
        assertThat(role.getSecretIdTtl(), is(SECRET_ID_TTL));
        assertThat(role.getEnableLocalSecretIds(), is(ENABLE_LOCAL_SECRET_IDS));
        assertThat(role.getTokenTtl(), is(TOKEN_TTL));
        assertThat(role.getTokenMaxTtl(), is(TOKEN_MAX_TTL));
        assertThat(role.getTokenBoundCidrs(), is(BOUND_CIDR_LIST));
        assertThat(role.getTokenExplicitMaxTtl(), is(TOKEN_EXPLICIT_MAX_TTL));
        assertThat(role.getTokenNoDefaultPolicy(), is(TOKEN_NO_DEFAULT_POLICY));
        assertThat(role.getTokenNumUses(), is(TOKEN_NUM_USES));
        assertThat(role.getTokenPeriod(), is(TOKEN_PERIOD));
        assertThat(role.getTokenType(), is(TOKEN_TYPE.value()));

        /* Verify that all parameters are included in JSON string */
        assertThat(new ObjectMapper().writeValueAsString(role), is(JSON_FULL));
    }

    /**
     * Test convenience methods
     */
    @Test
    void convenienceMethodsTest() {
        /* bind_secret_id */
        AppRole role = AppRole.builder(NAME).build();
        assertThat(role.getBindSecretId(), is(nullValue()));
        role = AppRole.builder(NAME).withBindSecretID().build();
        assertThat(role.getBindSecretId(), is(true));
        role = AppRole.builder(NAME).withoutBindSecretID().build();
        assertThat(role.getBindSecretId(), is(false));

        /* Add single CIDR subnet */
        role = AppRole.builder(NAME).withSecretBoundCidr(CIDR_2).withTokenBoundCidr(CIDR_2).build();
        assertThat(role.getSecretIdBoundCidrs(), hasSize(1));
        assertThat(role.getSecretIdBoundCidrs(), contains(CIDR_2));
        assertThat(role.getTokenBoundCidrs(), hasSize(1));
        assertThat(role.getTokenBoundCidrs(), contains(CIDR_2));
        role = AppRole.builder(NAME)
                .withSecretIdBoundCidrs(BOUND_CIDR_LIST)
                .withSecretBoundCidr(CIDR_2)
                .withTokenBoundCidrs(BOUND_CIDR_LIST)
                .withTokenBoundCidr(CIDR_2)
                .build();
        assertThat(role.getSecretIdBoundCidrs(), hasSize(2));
        assertThat(role.getSecretIdBoundCidrs(), contains(CIDR_1, CIDR_2));
        assertThat(role.getTokenBoundCidrs(), hasSize(2));
        assertThat(role.getSecretIdBoundCidrs(), contains(CIDR_1, CIDR_2));

        /* Add single policy */
        role = AppRole.builder(NAME).withTokenPolicy(POLICY_2).build();
        assertThat(role.getTokenPolicies(), hasSize(1));
        assertThat(role.getTokenPolicies(), contains(POLICY_2));
        role = AppRole.builder(NAME)
                .withTokenPolicies(POLICIES)
                .withTokenPolicy(POLICY_2)
                .build();
        assertThat(role.getTokenPolicies(), hasSize(2));
        assertThat(role.getTokenPolicies(), contains(POLICY, POLICY_2));
    }
}
