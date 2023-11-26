/*
 * Copyright 2016-2023 Stefan Kalscheuer
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

/**
 * JVaultConnector module.
 *
 * @author Stefan Kalscheuer
 */
module de.stklcode.jvault.connector {
    exports de.stklcode.jvault.connector;
    exports de.stklcode.jvault.connector.exception;
    exports de.stklcode.jvault.connector.model;
    exports de.stklcode.jvault.connector.model.response;
    exports de.stklcode.jvault.connector.model.response.embedded;

    opens de.stklcode.jvault.connector.model to com.fasterxml.jackson.databind;
    opens de.stklcode.jvault.connector.model.response to com.fasterxml.jackson.databind;
    opens de.stklcode.jvault.connector.model.response.embedded to com.fasterxml.jackson.databind;

    requires java.net.http;
    requires com.fasterxml.jackson.databind;
    requires com.fasterxml.jackson.datatype.jsr310;
}
