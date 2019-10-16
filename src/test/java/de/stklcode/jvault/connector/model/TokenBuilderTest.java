/*
 * Copyright 2016-2019 Stefan Kalscheuer
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

/**
 * JUnit Test for Token Builder.
 *
 * @author Stefan Kalscheuer
 * @since 0.4.0
 */
public class TokenBuilderTest {

    private static final String ID = "test-id";
    private static final String DISPLAY_NAME = "display-name";
    private static final Boolean NO_PARENT = false;
    private static final Boolean NO_DEFAULT_POLICY = false;
    private static final Integer TTL = 123;
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
    private static final String JSON_FULL = "{\"id\":\"test-id\",\"type\":\"service\",\"display_name\":\"display-name\",\"no_parent\":false,\"no_default_policy\":false,\"ttl\":123,\"num_uses\":4,\"policies\":[\"policy\"],\"meta\":{\"key\":\"value\"},\"renewable\":true}";

    @BeforeAll
    public static void init() {
        POLICIES.add(POLICY);
        META.put(META_KEY, META_VALUE);
    }

    /**
     * Build token without any parameters.
     */
    @Test
    public void buildDefaultTest() throws JsonProcessingException {
        Token token = new TokenBuilder().build();
        assertThat(token.getId(), is(nullValue()));
        assertThat(token.getType(), is(nullValue()));
        assertThat(token.getDisplayName(), is(nullValue()));
        assertThat(token.getNoParent(), is(nullValue()));
        assertThat(token.getNoDefaultPolicy(), is(nullValue()));
        assertThat(token.getTtl(), is(nullValue()));
        assertThat(token.getNumUses(), is(nullValue()));
        assertThat(token.getPolicies(), is(nullValue()));
        assertThat(token.getMeta(), is(nullValue()));
        assertThat(token.isRenewable(), is(nullValue()));

        /* optional fields should be ignored, so JSON string should be empty */
        assertThat(new ObjectMapper().writeValueAsString(token), is("{}"));
    }

    /**
     * Build token without all parameters set.
     */
    @Test
    public void buildFullTest() throws JsonProcessingException {
        Token token = new TokenBuilder()
                .withId(ID)
                .withType(Token.Type.SERVICE)
                .withDisplayName(DISPLAY_NAME)
                .withNoParent(NO_PARENT)
                .withNoDefaultPolicy(NO_DEFAULT_POLICY)
                .withTtl(TTL)
                .withNumUses(NUM_USES)
                .withPolicies(POLICIES)
                .withMeta(META)
                .withRenewable(RENEWABLE)
                .build();
        assertThat(token.getId(), is(ID));
        assertThat(token.getType(), is(Token.Type.SERVICE.value()));
        assertThat(token.getDisplayName(), is(DISPLAY_NAME));
        assertThat(token.getNoParent(), is(NO_PARENT));
        assertThat(token.getNoDefaultPolicy(), is(NO_DEFAULT_POLICY));
        assertThat(token.getTtl(), is(TTL));
        assertThat(token.getNumUses(), is(NUM_USES));
        assertThat(token.getPolicies(), is(POLICIES));
        assertThat(token.getMeta(), is(META));
        assertThat(token.isRenewable(), is(RENEWABLE));

        /* Verify that all parameters are included in JSON string */
        assertThat(new ObjectMapper().writeValueAsString(token), is(JSON_FULL));
    }

    /**
     * Test convenience methods
     */
    @Test
    public void convenienceMethodsTest() {
        /* Parent */
        Token token = new TokenBuilder().asOrphan().build();
        assertThat(token.getNoParent(), is(true));
        token = new TokenBuilder().withParent().build();
        assertThat(token.getNoParent(), is(false));

        /* Default policy */
        token = new TokenBuilder().withDefaultPolicy().build();
        assertThat(token.getNoDefaultPolicy(), is(false));
        token = new TokenBuilder().withoutDefaultPolicy().build();
        assertThat(token.getNoDefaultPolicy(), is(true));

        /* Renewability */
        token = new TokenBuilder().renewable().build();
        assertThat(token.isRenewable(), is(true));
        token = new TokenBuilder().notRenewable().build();
        assertThat(token.isRenewable(), is(false));

        /* Add single policy */
        token = new TokenBuilder().withPolicy(POLICY_2).build();
        assertThat(token.getPolicies(), hasSize(1));
        assertThat(token.getPolicies(), contains(POLICY_2));
        token = new TokenBuilder()
                .withPolicies(POLICY, POLICY_2)
                .withPolicy(POLICY_3)
                .build();
        assertThat(token.getPolicies(), hasSize(3));
        assertThat(token.getPolicies(), contains(POLICY, POLICY_2, POLICY_3));

        /* Add single metadata */
        token = new TokenBuilder().withMeta(META_KEY_2, META_VALUE_2).build();
        assertThat(token.getMeta().size(), is(1));
        assertThat(token.getMeta().keySet(), contains(META_KEY_2));
        assertThat(token.getMeta().get(META_KEY_2), is(META_VALUE_2));
        token = new TokenBuilder()
                .withMeta(META)
                .withMeta(META_KEY_2, META_VALUE_2)
                .build();
        assertThat(token.getMeta().size(), is(2));
        assertThat(token.getMeta().get(META_KEY), is(META_VALUE));
        assertThat(token.getMeta().get(META_KEY_2), is(META_VALUE_2));
    }
}
