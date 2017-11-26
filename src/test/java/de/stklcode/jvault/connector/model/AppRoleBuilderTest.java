/*
 * Copyright 2016-2017 Stefan Kalscheuer
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
 * JUnit Test for AppRole Builder.
 *
 * @author Stefan Kalscheuer
 * @since 0.4.0
 */
public class AppRoleBuilderTest {


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
    private static final Integer TOKEN_TTL = 4800;
    private static final Integer TOKEN_MAX_TTL = 9600;
    private static final Integer PERIOD = 1234;
    private static final String JSON_MIN = "{\"role_name\":\"" + NAME + "\"}";
    private static final String JSON_FULL = String.format("{\"role_name\":\"%s\",\"role_id\":\"%s\",\"bind_secret_id\":%s,\"bound_cidr_list\":\"%s\",\"policies\":\"%s\",\"secret_id_num_uses\":%d,\"secret_id_ttl\":%d,\"token_ttl\":%d,\"token_max_ttl\":%d,\"period\":%d}",
            NAME, ID, BIND_SECRET_ID, CIDR_1, POLICY, SECRET_ID_NUM_USES, SECRET_ID_TTL, TOKEN_TTL, TOKEN_MAX_TTL, PERIOD);

    @BeforeAll
    public static void init() {
        BOUND_CIDR_LIST.add(CIDR_1);
        POLICIES.add(POLICY);
    }

    /**
     * Build role with only a name.
     */
    @Test
    public void buildDefaultTest() throws JsonProcessingException {
        AppRole role = new AppRoleBuilder(NAME).build();
        assertThat(role.getId(), is(nullValue()));
        assertThat(role.getBindSecretId(), is(nullValue()));
        assertThat(role.getBoundCidrList(), is(nullValue()));
        assertThat(role.getPolicies(), is(nullValue()));
        assertThat(role.getSecretIdNumUses(), is(nullValue()));
        assertThat(role.getSecretIdTtl(), is(nullValue()));
        assertThat(role.getTokenTtl(), is(nullValue()));
        assertThat(role.getTokenMaxTtl(), is(nullValue()));
        assertThat(role.getPeriod(), is(nullValue()));

        /* optional fields should be ignored, so JSON string should only contain role_name */
        assertThat(new ObjectMapper().writeValueAsString(role), is(JSON_MIN));
    }

    /**
     * Build token without all parameters set.
     */
    @Test
    public void buildFullTest() throws JsonProcessingException {
        AppRole role = new AppRoleBuilder(NAME)
                .withId(ID)
                .withBindSecretID(BIND_SECRET_ID)
                .withBoundCidrList(BOUND_CIDR_LIST)
                .withPolicies(POLICIES)
                .withSecretIdNumUses(SECRET_ID_NUM_USES)
                .withSecretIdTtl(SECRET_ID_TTL)
                .withTokenTtl(TOKEN_TTL)
                .withTokenMaxTtl(TOKEN_MAX_TTL)
                .withPeriod(PERIOD)
                .build();
        assertThat(role.getName(), is(NAME));
        assertThat(role.getId(), is(ID));
        assertThat(role.getBindSecretId(), is(BIND_SECRET_ID));
        assertThat(role.getBoundCidrList(), is(BOUND_CIDR_LIST));
        assertThat(role.getPolicies(), is(POLICIES));
        assertThat(role.getSecretIdNumUses(), is(SECRET_ID_NUM_USES));
        assertThat(role.getSecretIdTtl(), is(SECRET_ID_TTL));
        assertThat(role.getTokenTtl(), is(TOKEN_TTL));
        assertThat(role.getTokenMaxTtl(), is(TOKEN_MAX_TTL));
        assertThat(role.getPeriod(), is(PERIOD));

        /* Verify that all parameters are included in JSON string */
        assertThat(new ObjectMapper().writeValueAsString(role), is(JSON_FULL));
    }

    /**
     * Test convenience methods
     */
    @Test
    public void convenienceMethodsTest() {
        /* bind_secret_id */
        AppRole role = new AppRoleBuilder(NAME).build();
        assertThat(role.getBindSecretId(), is(nullValue()));
        role = new AppRoleBuilder(NAME).withBindSecretID().build();
        assertThat(role.getBindSecretId(), is(true));
        role = new AppRoleBuilder(NAME).withoutBindSecretID().build();
        assertThat(role.getBindSecretId(), is(false));

        /* Add single CIDR subnet */
        role = new AppRoleBuilder(NAME).withCidrBlock(CIDR_2).build();
        assertThat(role.getBoundCidrList(), hasSize(1));
        assertThat(role.getBoundCidrList(), contains(CIDR_2));
        role = new AppRoleBuilder(NAME)
                .withBoundCidrList(BOUND_CIDR_LIST)
                .withCidrBlock(CIDR_2)
                .build();
        assertThat(role.getBoundCidrList(), hasSize(2));
        assertThat(role.getBoundCidrList(), contains(CIDR_1, CIDR_2));

        /* Add single policy */
        role = new AppRoleBuilder(NAME).withPolicy(POLICY_2).build();
        assertThat(role.getPolicies(), hasSize(1));
        assertThat(role.getPolicies(), contains(POLICY_2));
        role = new AppRoleBuilder(NAME)
                .withPolicies(POLICIES)
                .withPolicy(POLICY_2)
                .build();
        assertThat(role.getPolicies(), hasSize(2));
        assertThat(role.getPolicies(), contains(POLICY, POLICY_2));
    }
}
