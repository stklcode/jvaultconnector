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

import org.junit.Test;

import static org.hamcrest.Matchers.*;
import static org.junit.Assert.assertThat;

/**
 * JUnit Test for AuthBackend model.
 *
 * @author Stefan Kalscheuer
 * @since 0.4.0
 */
public class AuthBackendTest {

    /**
     * Test forType() method.
     */
    @Test
    public void forTypeTest() {
        assertThat(AuthBackend.forType("token"), is(AuthBackend.TOKEN));
        assertThat(AuthBackend.forType("app-id"), is(AuthBackend.APPID));
        assertThat(AuthBackend.forType("userpass"), is(AuthBackend.USERPASS));
        assertThat(AuthBackend.forType("github"), is(AuthBackend.GITHUB));
        assertThat(AuthBackend.forType(""), is(AuthBackend.UNKNOWN));
        assertThat(AuthBackend.forType("foobar"), is(AuthBackend.UNKNOWN));
    }

}
