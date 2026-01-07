/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.guacamole.vault.ksm.secret;

import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

import javax.annotation.Nonnull;

/**
 * Utility class for extracting custom field matching criteria from connection
 * parameters. Custom field matching allows administrators to filter KSM records
 * based on arbitrary custom field labels using connection parameters with the
 * pattern "ksm-match-{label}={value}".
 */
public class CustomFieldMatchCriteria {

    /**
     * Prefix for custom field match parameters. Parameters with this prefix
     * specify criteria for matching KSM records by custom field values.
     * For example, "ksm-match-environment=production" would match records
     * with a custom field labeled "environment" having value "production".
     */
    public static final String MATCH_PREFIX = "ksm-match-";

    /**
     * Prefix for gateway custom field match parameters. Parameters with this
     * prefix specify criteria for matching KSM records used for RDP gateway
     * credentials. For example, "ksm-gateway-match-role=admin" would match
     * gateway credential records with a custom field labeled "role" having
     * value "admin".
     */
    public static final String GATEWAY_MATCH_PREFIX = "ksm-gateway-match-";

    /**
     * This class should not be instantiated.
     */
    private CustomFieldMatchCriteria() {}

    /**
     * Extracts custom field match criteria from the given connection parameters.
     * Parameters whose names start with the specified prefix are extracted,
     * with the prefix stripped to obtain the custom field label. Labels are
     * converted to lowercase for case-insensitive matching. Values are preserved
     * as-is for exact matching.
     *
     * @param parameters
     *     The connection parameters to extract criteria from. May be null.
     *
     * @param prefix
     *     The parameter prefix to look for (e.g., {@link #MATCH_PREFIX} or
     *     {@link #GATEWAY_MATCH_PREFIX}).
     *
     * @return
     *     An unmodifiable map of custom field labels (lowercase) to expected
     *     values. Returns an empty map if no matching parameters are found
     *     or if parameters is null.
     */
    @Nonnull
    public static Map<String, String> extractCriteria(
            Map<String, String> parameters, @Nonnull String prefix) {

        // Return empty map if no parameters provided
        if (parameters == null || parameters.isEmpty())
            return Collections.emptyMap();

        Map<String, String> criteria = new HashMap<>();

        // Extract all parameters with the specified prefix
        for (Map.Entry<String, String> entry : parameters.entrySet()) {

            String paramName = entry.getKey();
            String paramValue = entry.getValue();

            // Skip parameters that don't start with the prefix
            if (paramName == null || !paramName.toLowerCase(Locale.ROOT)
                    .startsWith(prefix.toLowerCase(Locale.ROOT)))
                continue;

            // Skip parameters with null or empty values
            if (paramValue == null || paramValue.isEmpty())
                continue;

            // Extract the label by stripping the prefix, convert to lowercase
            String label = paramName.substring(prefix.length())
                    .toLowerCase(Locale.ROOT);

            // Skip if the label is empty after stripping prefix
            if (label.isEmpty())
                continue;

            // Store the criteria with lowercase label and exact value
            criteria.put(label, paramValue);

        }

        return Collections.unmodifiableMap(criteria);

    }

}
