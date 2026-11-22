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

package de.stklcode.jvault.connector.internal;

import java.util.Collection;
import java.util.Map;
import java.util.StringJoiner;

/**
 * Builder for {@code toString()} representations of model records that hold sensitive or lengthy values.
 * <p>
 * The output follows the format of the implicit {@link Record#toString()}, i.e. {@code Name[a=1, b=2]}.
 * Sensitive values are replaced by {@value #MASK}, {@code null} values are always printed as {@code null}.
 *
 * @author Stefan Kalscheuer
 * @since 2.0.0
 */
public final class ToStringBuilder {
    private static final String MASK = "***";
    private static final String NULL = "null";

    private final StringJoiner joiner;

    /**
     * Create a new builder.
     *
     * @param name Record name.
     */
    private ToStringBuilder(final String name) {
        this.joiner = new StringJoiner(", ", name + "[", "]");
    }

    /**
     * Create a new builder.
     *
     * @param name Record name, e.g. {@code "TokenData"}.
     * @return The builder
     */
    public static ToStringBuilder of(final String name) {
        return new ToStringBuilder(name);
    }

    /**
     * Add a plain field.
     *
     * @param name  Field name.
     * @param value Field value.
     * @return self
     */
    public ToStringBuilder add(final String name, final Object value) {
        return append(name, String.valueOf(value));
    }

    /**
     * Add a masked field, printed as {@value #MASK} (or {@code null}).
     *
     * @param name  Field name.
     * @param value Field value.
     * @return self
     */
    public ToStringBuilder masked(final String name, final Object value) {
        return append(name, value == null ? NULL : MASK);
    }

    /**
     * Add a map field with visible keys and masked values, e.g. {@code {username=***, password=***}}.
     *
     * @param name  Field name.
     * @param value Field value.
     * @return self
     */
    public ToStringBuilder maskedValues(final String name, final Map<?, ?> value) {
        if (value == null) {
            return append(name, NULL);
        }

        var map = new StringJoiner(", ", "{", "}");
        value.forEach((k, v) -> map.add(k + "=" + (v == null ? NULL : MASK)));
        return append(name, map.toString());
    }

    /**
     * Add a long string field, printed by its length only, e.g. {@code <1234 chars>}.
     *
     * @param name  Field name.
     * @param value Field value.
     * @return self
     */
    public ToStringBuilder summarized(final String name, final String value) {
        return append(name, value == null ? NULL : "<" + value.length() + " chars>");
    }

    /**
     * Add a collection field, printed by its size only, e.g. {@code <3 entries>}.
     *
     * @param name  Field name.
     * @param value Field value.
     * @return self
     */
    public ToStringBuilder summarized(final String name, final Collection<?> value) {
        return append(name, value == null ? NULL : "<" + value.size() + " entries>");
    }

    /**
     * Add a string field, abbreviated to the given number of leading characters if longer.
     *
     * @param name      Field name.
     * @param value     Field value.
     * @param maxLength Maximum number of characters to print.
     * @return self
     */
    public ToStringBuilder abbreviated(final String name, final String value, final int maxLength) {
        if (value == null || value.length() <= maxLength) {
            return append(name, String.valueOf(value));
        }
        return append(name, value.substring(0, maxLength) + "…<" + value.length() + " chars>");
    }

    private ToStringBuilder append(final String name, final String value) {
        joiner.add(name + "=" + value);
        return this;
    }

    @Override
    public String toString() {
        return joiner.toString();
    }
}
