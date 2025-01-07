/*
 * Copyright 2016-2025 Stefan Kalscheuer
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

import static org.junit.jupiter.api.Assertions.assertEquals;


/**
 * JUnit Test for AuthBackend model.
 *
 * @author Stefan Kalscheuer
 * @since 0.4.0
 */
class AuthBackendTest {

    /**
     * Test forType() method.
     */
    @Test
    void forTypeTest() {
        assertEquals(AuthBackend.TOKEN, AuthBackend.forType("token"));
        assertEquals(AuthBackend.USERPASS, AuthBackend.forType("userpass"));
        assertEquals(AuthBackend.GITHUB, AuthBackend.forType("github"));
        assertEquals(AuthBackend.UNKNOWN, AuthBackend.forType(""));
        assertEquals(AuthBackend.UNKNOWN, AuthBackend.forType("foobar"));
    }
}
