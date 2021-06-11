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

package de.stklcode.jvault.connector.builder;

/**
 * Vault Connector Builder implementation for HTTP Vault connectors.
 *
 * @author Stefan Kalscheuer
 * @since 0.8.0
 * @since 0.9.5 Extends new class for migration purposes only.
 * @deprecated Use {@link de.stklcode.jvault.connector.HTTPVaultConnectorBuilder} instead. Will be removed in 1.0
 */
@Deprecated
public class HTTPVaultConnectorBuilder extends de.stklcode.jvault.connector.HTTPVaultConnectorBuilder {
    public HTTPVaultConnectorBuilder() {
        super();
    }
}
