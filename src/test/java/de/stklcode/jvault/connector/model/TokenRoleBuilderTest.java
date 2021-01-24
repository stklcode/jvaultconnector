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
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

/**
 * Unit Test for {@link Token.Builder}
 *
 * @author Stefan Kalscheuer
 * @since 0.9
 */
class TokenRoleBuilderTest {
    private static final String NAME = "test-role";
    private static final String ALLOWED_POLICY_1 = "apol-1";
    private static final String ALLOWED_POLICY_2 = "apol-2";
    private static final String ALLOWED_POLICY_3 = "apol-3";
    private static final List<String> ALLOWED_POLICIES = Arrays.asList(ALLOWED_POLICY_1, ALLOWED_POLICY_2);
    private static final String DISALLOWED_POLICY_1 = "dpol-1";
    private static final String DISALLOWED_POLICY_2 = "dpol-2";
    private static final String DISALLOWED_POLICY_3 = "dpol-3";
    private static final List<String> DISALLOWED_POLICIES = Arrays.asList(DISALLOWED_POLICY_2, DISALLOWED_POLICY_3);
    private static final Boolean ORPHAN = false;
    private static final Boolean RENEWABLE = true;
    private static final String PATH_SUFFIX = "ps";
    private static final String ALLOWED_ENTITY_ALIAS_1 = "alias-1";
    private static final String ALLOWED_ENTITY_ALIAS_2 = "alias-2";
    private static final String ALLOWED_ENTITY_ALIAS_3 = "alias-3";
    private static final List<String> ALLOWED_ENTITY_ALIASES = Arrays.asList(ALLOWED_ENTITY_ALIAS_1, ALLOWED_ENTITY_ALIAS_3);
    private static final String TOKEN_BOUND_CIDR_1 = "192.0.2.0/24";
    private static final String TOKEN_BOUND_CIDR_2 = "198.51.100.0/24";
    private static final String TOKEN_BOUND_CIDR_3 = "203.0.113.0/24";
    private static final List<String> TOKEN_BOUND_CIDRS = Arrays.asList(TOKEN_BOUND_CIDR_2, TOKEN_BOUND_CIDR_1);
    private static final Integer TOKEN_EXPLICIT_MAX_TTL = 1234;
    private static final Boolean TOKEN_NO_DEFAULT_POLICY = false;
    private static final Integer TOKEN_NUM_USES = 5;
    private static final Integer TOKEN_PERIOD = 2345;
    private static final Token.Type TOKEN_TYPE = Token.Type.SERVICE;

    private static final String JSON_FULL = "{" +
            "\"name\":\"" + NAME + "\"," +
            "\"allowed_policies\":[\"" + ALLOWED_POLICY_1 + "\",\"" + ALLOWED_POLICY_2 + "\",\"" + ALLOWED_POLICY_3 + "\"]," +
            "\"disallowed_policies\":[\"" + DISALLOWED_POLICY_1 + "\",\"" + DISALLOWED_POLICY_2 + "\",\"" + DISALLOWED_POLICY_3 + "\"]," +
            "\"orphan\":" + ORPHAN + "," +
            "\"renewable\":" + RENEWABLE + "," +
            "\"path_suffix\":\"" + PATH_SUFFIX + "\"," +
            "\"allowed_entity_aliases\":[\"" + ALLOWED_ENTITY_ALIAS_1 + "\",\"" + ALLOWED_ENTITY_ALIAS_3 + "\",\"" + ALLOWED_ENTITY_ALIAS_2 + "\"]," +
            "\"token_bound_cidrs\":[\"" + TOKEN_BOUND_CIDR_3 + "\",\"" + TOKEN_BOUND_CIDR_2 + "\",\"" + TOKEN_BOUND_CIDR_1 + "\"]," +
            "\"token_explicit_max_ttl\":" + TOKEN_EXPLICIT_MAX_TTL + "," +
            "\"token_no_default_policy\":" + TOKEN_NO_DEFAULT_POLICY + "," +
            "\"token_num_uses\":" + TOKEN_NUM_USES + "," +
            "\"token_period\":" + TOKEN_PERIOD + "," +
            "\"token_type\":\"" + TOKEN_TYPE.value() + "\"}";

    /**
     * Build token without any parameters.
     */
    @Test
    void buildDefaultTest() throws JsonProcessingException {
        TokenRole role = TokenRole.builder().build();
        assertThat(role.getAllowedPolicies(), is(nullValue()));
        assertThat(role.getDisallowedPolicies(), is(nullValue()));
        assertThat(role.getOrphan(), is(nullValue()));
        assertThat(role.getRenewable(), is(nullValue()));
        assertThat(role.getAllowedEntityAliases(), is(nullValue()));
        assertThat(role.getTokenBoundCidrs(), is(nullValue()));
        assertThat(role.getTokenExplicitMaxTtl(), is(nullValue()));
        assertThat(role.getTokenNoDefaultPolicy(), is(nullValue()));
        assertThat(role.getTokenNumUses(), is(nullValue()));
        assertThat(role.getTokenPeriod(), is(nullValue()));
        assertThat(role.getTokenType(), is(nullValue()));

        /* optional fields should be ignored, so JSON string should be empty */
        assertThat(new ObjectMapper().writeValueAsString(role), is("{}"));
    }

    /**
     * Build token without all parameters NULL.
     */
    @Test
    void buildNullTest() throws JsonProcessingException {
        TokenRole role = TokenRole.builder()
                .forName(null)
                .withAllowedPolicies(null)
                .withAllowedPolicy(null)
                .withDisallowedPolicy(null)
                .withDisallowedPolicies(null)
                .orphan(null)
                .renewable(null)
                .withPathSuffix(null)
                .withAllowedEntityAliases(null)
                .withAllowedEntityAlias(null)
                .withTokenBoundCidr(null)
                .withTokenBoundCidrs(null)
                .withTokenExplicitMaxTtl(null)
                .withTokenNoDefaultPolicy(null)
                .withTokenNumUses(null)
                .withTokenPeriod(null)
                .withTokenType(null)
                .build();

        assertThat(role.getAllowedPolicies(), is(nullValue()));
        assertThat(role.getDisallowedPolicies(), is(nullValue()));
        assertThat(role.getOrphan(), is(nullValue()));
        assertThat(role.getRenewable(), is(nullValue()));
        assertThat(role.getAllowedEntityAliases(), is(nullValue()));
        assertThat(role.getTokenBoundCidrs(), is(nullValue()));
        assertThat(role.getTokenExplicitMaxTtl(), is(nullValue()));
        assertThat(role.getTokenNoDefaultPolicy(), is(nullValue()));
        assertThat(role.getTokenNumUses(), is(nullValue()));
        assertThat(role.getTokenPeriod(), is(nullValue()));
        assertThat(role.getTokenType(), is(nullValue()));

        /* optional fields should be ignored, so JSON string should be empty */
        assertThat(new ObjectMapper().writeValueAsString(role), is("{}"));
    }

    /**
     * Build token without all parameters set.
     */
    @Test
    void buildFullTest() throws JsonProcessingException {
        TokenRole role = TokenRole.builder()
                .forName(NAME)
                .withAllowedPolicies(ALLOWED_POLICIES)
                .withAllowedPolicy(ALLOWED_POLICY_3)
                .withDisallowedPolicy(DISALLOWED_POLICY_1)
                .withDisallowedPolicies(DISALLOWED_POLICIES)
                .orphan(ORPHAN)
                .renewable(RENEWABLE)
                .withPathSuffix(PATH_SUFFIX)
                .withAllowedEntityAliases(ALLOWED_ENTITY_ALIASES)
                .withAllowedEntityAlias(ALLOWED_ENTITY_ALIAS_2)
                .withTokenBoundCidr(TOKEN_BOUND_CIDR_3)
                .withTokenBoundCidrs(TOKEN_BOUND_CIDRS)
                .withTokenExplicitMaxTtl(TOKEN_EXPLICIT_MAX_TTL)
                .withTokenNoDefaultPolicy(TOKEN_NO_DEFAULT_POLICY)
                .withTokenNumUses(TOKEN_NUM_USES)
                .withTokenPeriod(TOKEN_PERIOD)
                .withTokenType(TOKEN_TYPE)
                .build();
        assertThat(role.getName(), is(NAME));
        assertThat(role.getAllowedPolicies(), hasSize(ALLOWED_POLICIES.size() + 1));
        assertThat(role.getAllowedPolicies(), containsInAnyOrder(ALLOWED_POLICY_1, ALLOWED_POLICY_2, ALLOWED_POLICY_3));
        assertThat(role.getDisallowedPolicies(), hasSize(DISALLOWED_POLICIES.size() + 1));
        assertThat(role.getDisallowedPolicies(), containsInAnyOrder(DISALLOWED_POLICY_1, DISALLOWED_POLICY_2, DISALLOWED_POLICY_3));
        assertThat(role.getOrphan(), is(ORPHAN));
        assertThat(role.getRenewable(), is(RENEWABLE));
        assertThat(role.getPathSuffix(), is(PATH_SUFFIX));
        assertThat(role.getAllowedEntityAliases(), hasSize(ALLOWED_ENTITY_ALIASES.size() + 1));
        assertThat(role.getAllowedEntityAliases(), containsInAnyOrder(ALLOWED_ENTITY_ALIAS_1, ALLOWED_ENTITY_ALIAS_2, ALLOWED_ENTITY_ALIAS_3));
        assertThat(role.getTokenBoundCidrs(), hasSize(TOKEN_BOUND_CIDRS.size() + 1));
        assertThat(role.getTokenBoundCidrs(), containsInAnyOrder(TOKEN_BOUND_CIDR_1, TOKEN_BOUND_CIDR_2, TOKEN_BOUND_CIDR_3));
        assertThat(role.getTokenNoDefaultPolicy(), is(TOKEN_NO_DEFAULT_POLICY));
        assertThat(role.getTokenNumUses(), is(TOKEN_NUM_USES));
        assertThat(role.getTokenPeriod(), is(TOKEN_PERIOD));
        assertThat(role.getTokenType(), is(TOKEN_TYPE.value()));

        /* Verify that all parameters are included in JSON string */
        assertThat(new ObjectMapper().writeValueAsString(role), is(JSON_FULL));
    }
}
