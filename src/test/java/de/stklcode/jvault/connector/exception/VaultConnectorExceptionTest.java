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

package de.stklcode.jvault.connector.exception;

import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.instanceOf;
import static org.hamcrest.Matchers.nullValue;
import static org.hamcrest.core.Is.is;

/**
 * Common JUnit test for Exceptions extending {@link VaultConnectorException}.
 *
 * @author Stefan Kalscheuer
 * @since 0.6.2
 */
public class VaultConnectorExceptionTest {
    private static final String MSG = "This is a test exception!";
    private static final Throwable CAUSE = new Exception("Test-Cause");
    private static final Integer STATUS_CODE = 1337;
    private static final String RESPONSE = "Dummy response";

    @Test
    public void authorizationRequiredExceptionTest() {
        assertEmptyConstructor(new AuthorizationRequiredException());
    }

    @Test
    public void connectionExceptionTest() {
        assertEmptyConstructor(new ConnectionException());
        assertMsgConstructor(new ConnectionException(MSG));
        assertCauseConstructor(new ConnectionException(CAUSE));
        assertMsgCauseConstructor(new ConnectionException(MSG, CAUSE));
    }

    @Test
    public void invalidRequestExceptionTest() {
        assertEmptyConstructor(new InvalidRequestException());
        assertMsgConstructor(new InvalidRequestException(MSG));
        assertCauseConstructor(new InvalidRequestException(CAUSE));
        assertMsgCauseConstructor(new InvalidRequestException(MSG, CAUSE));
    }

    @Test
    public void invalidResponseExceptionTest() {
        assertEmptyConstructor(new InvalidResponseException());
        assertMsgConstructor(new InvalidResponseException(MSG));
        assertCauseConstructor(new InvalidResponseException(CAUSE));
        assertMsgCauseConstructor(new InvalidResponseException(MSG, CAUSE));

        // Constructor with message and status code.
        InvalidResponseException e = new InvalidResponseException(MSG, STATUS_CODE);
        assertThat(e.getMessage(), is(MSG));
        assertThat(e.getCause(), is(nullValue()));
        assertThat(e.getStatusCode(), is(STATUS_CODE));
        assertThat(e.getResponse(), is(nullValue()));

        // Constructor with message, status code and cause.
        e = new InvalidResponseException(MSG, STATUS_CODE, CAUSE);
        assertThat(e.getMessage(), is(MSG));
        assertThat(e.getCause(), is(CAUSE));
        assertThat(e.getStatusCode(), is(STATUS_CODE));
        assertThat(e.getResponse(), is(nullValue()));

        // Constructor with message, status code and response.
        e = new InvalidResponseException(MSG, STATUS_CODE, RESPONSE);
        assertThat(e.getMessage(), is(MSG));
        assertThat(e.getCause(), is(nullValue()));
        assertThat(e.getStatusCode(), is(STATUS_CODE));
        assertThat(e.getResponse(), is(RESPONSE));

        // Constructor with message, status code, response and cause.
        e = new InvalidResponseException(MSG, STATUS_CODE, RESPONSE, CAUSE);
        assertThat(e.getMessage(), is(MSG));
        assertThat(e.getCause(), is(CAUSE));
        assertThat(e.getStatusCode(), is(STATUS_CODE));
        assertThat(e.getResponse(), is(RESPONSE));
    }

    @Test
    public void permissionDeniedExceptionTest() {
        // Default message overwritten.
        PermissionDeniedException e = new PermissionDeniedException();
        assertThat(e, is(instanceOf(VaultConnectorException.class)));
        assertThat(e, is(instanceOf(Exception.class)));
        assertThat(e, is(instanceOf(Throwable.class)));
        assertThat(e.getMessage(), is("Permission denied"));
        assertThat(e.getCause(), is(nullValue()));

        assertMsgConstructor(new PermissionDeniedException(MSG));
        assertCauseConstructor(new PermissionDeniedException(CAUSE));
        assertMsgCauseConstructor(new PermissionDeniedException(MSG, CAUSE));
    }

    @Test
    public void tlsExceptionTest() {
        assertEmptyConstructor(new TlsException());
        assertMsgConstructor(new TlsException(MSG));
        assertCauseConstructor(new TlsException(CAUSE));
        assertMsgCauseConstructor(new TlsException(MSG, CAUSE));
    }

    /**
     * Assertions for empty constructor.
     *
     * @param e the exception
     */
    private void assertEmptyConstructor(VaultConnectorException e) {
        assertThat(e, is(instanceOf(VaultConnectorException.class)));
        assertThat(e, is(instanceOf(Exception.class)));
        assertThat(e, is(instanceOf(Throwable.class)));
        assertThat(e.getMessage(), is(nullValue()));
        assertThat(e.getCause(), is(nullValue()));
    }

    /**
     * Assertions for constructor with message.
     *
     * @param e the exception
     */
    private void assertMsgConstructor(VaultConnectorException e) {
        assertThat(e.getMessage(), is(MSG));
        assertThat(e.getCause(), is(nullValue()));
    }

    /**
     * Assertions for constructor with cause.
     *
     * @param e the exception
     */
    private void assertCauseConstructor(VaultConnectorException e) {
        assertThat(e.getMessage(), is(CAUSE.toString()));
        assertThat(e.getCause(), is(CAUSE));
    }

    /**
     * Assertions for constructor with message and cause.
     *
     * @param e the exception
     */
    private void assertMsgCauseConstructor(VaultConnectorException e) {
        assertThat(e.getMessage(), is(MSG));
        assertThat(e.getCause(), is(CAUSE));
    }
}
