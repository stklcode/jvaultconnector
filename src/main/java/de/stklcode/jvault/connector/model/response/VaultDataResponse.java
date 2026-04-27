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

package de.stklcode.jvault.connector.model.response;

import de.stklcode.jvault.connector.model.response.embedded.AuthData;
import de.stklcode.jvault.connector.model.response.embedded.WrapInfo;

import java.io.Serializable;
import java.util.List;

/**
 * Abstract Vault response with default payload fields.
 *
 * @author Stefan Kalscheuer
 * @since 0.1
 * @since 2.0 abstract class is now an interface
 */
public interface VaultDataResponse extends VaultResponse {

    /**
     * This method returns the responseMeta wrapper for the data response.
     * Primarily designed for internal use, getters delegate to the nested attributes directly.
     *
     * @return Data response responseMeta wrapper
     * @since 2.0
     */
    Header responseHeader();

    /**
     * @return Request ID
     * @since 1.1
     */
    default String requestId() {
        return responseHeader().requestId();
    }

    /**
     * @return Lease ID
     */
    default String leaseId() {
        return responseHeader().leaseId();
    }

    /**
     * @return Lease is renewable
     */
    default Boolean renewable() {
        return responseHeader().renewable();
    }

    /**
     * @return Lease duration
     */
    default Integer leaseDuration() {
        return responseHeader().leaseDuration;
    }

    /**
     * @return List of warnings
     */
    default List<String> warnings() {
        return responseHeader().warnings();
    }

    /**
     * @return Wrapping information
     * @since 1.1
     */
    default WrapInfo wrapInfo() {
        return responseHeader().wrapInfo();
    }

    /**
     * @return Authentication information for this response
     * @since 1.3
     */
    default AuthData auth() {
        return responseHeader().auth();
    }

    /**
     * @return Information about the type of mount this secret is from (since Vault 1.17)
     * @since 1.3
     */
    default String mountType() {
        return responseHeader().mountType;
    }


    /**
     * Embedded record for common ("responseMeta") attributes of each {@link VaultDataResponse}.
     *
     * @param requestId     Request ID
     * @param leaseId       Lease ID
     * @param renewable     Lease is renewable
     * @param leaseDuration Lease duration
     * @param warnings      List of warnings
     * @param wrapInfo      Wrapping information
     * @param auth          Authentication information for this response
     * @param mountType     Information about the type of mount this secret is from (since Vault 1.17)
     * @since 2.0
     */
    record Header(
        String requestId,
        String leaseId,
        Boolean renewable,
        Integer leaseDuration,
        List<String> warnings,
        WrapInfo wrapInfo,
        AuthData auth,
        String mountType
    ) implements Serializable {
    }
}
