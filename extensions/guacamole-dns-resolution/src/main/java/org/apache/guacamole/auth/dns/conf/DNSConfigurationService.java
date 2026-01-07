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

package org.apache.guacamole.auth.dns.conf;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.environment.Environment;
import org.apache.guacamole.environment.LocalEnvironment;
import org.apache.guacamole.properties.BooleanGuacamoleProperty;
import org.apache.guacamole.properties.IntegerGuacamoleProperty;
import org.apache.guacamole.properties.StringGuacamoleProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Service for retrieving DNS resolution extension configuration.
 * Configuration can be provided via environment variables (preferred for
 * Docker/Kubernetes) or guacamole.properties file.
 * 
 * <p>Environment variables (checked first):</p>
 * <ul>
 *   <li>DNS_RESOLUTION_SERVER - DNS server address (IP or hostname)</li>
 *   <li>DNS_RESOLUTION_PORT - DNS server port (default: 53)</li>
 *   <li>DNS_RESOLUTION_TIMEOUT - Timeout in milliseconds (default: 5000)</li>
 *   <li>DNS_RESOLUTION_CACHE_TTL - Cache TTL in seconds (default: 300)</li>
 *   <li>DNS_RESOLUTION_RESOLVE_GATEWAY - Resolve RDP gateway hostnames (default: true)</li>
 * </ul>
 * 
 * <p>Properties file fallback (guacamole.properties):</p>
 * <ul>
 *   <li>dns-resolution-server</li>
 *   <li>dns-resolution-port</li>
 *   <li>dns-resolution-timeout</li>
 *   <li>dns-resolution-cache-ttl</li>
 *   <li>dns-resolution-resolve-gateway</li>
 * </ul>
 */
public class DNSConfigurationService {

    /**
     * Logger for this class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(DNSConfigurationService.class);

    /**
     * The Guacamole server environment.
     */
    private final Environment environment;

    /**
     * Environment variable name for DNS server.
     */
    private static final String ENV_DNS_SERVER = "DNS_RESOLUTION_SERVER";

    /**
     * Environment variable name for DNS port.
     */
    private static final String ENV_DNS_PORT = "DNS_RESOLUTION_PORT";

    /**
     * Environment variable name for DNS timeout.
     */
    private static final String ENV_DNS_TIMEOUT = "DNS_RESOLUTION_TIMEOUT";

    /**
     * Environment variable name for cache TTL.
     */
    private static final String ENV_DNS_CACHE_TTL = "DNS_RESOLUTION_CACHE_TTL";

    /**
     * Environment variable name for gateway resolution.
     */
    private static final String ENV_DNS_RESOLVE_GATEWAY = "DNS_RESOLUTION_RESOLVE_GATEWAY";

    /**
     * Property for the DNS server address. Can be an IP address or hostname
     * (e.g., a Kubernetes service name like "kube-dns.kube-system.svc.cluster.local").
     */
    private static final StringGuacamoleProperty DNS_SERVER = new StringGuacamoleProperty() {
        @Override
        public String getName() {
            return "dns-resolution-server";
        }
    };

    /**
     * Property for the DNS server port. Default is 53.
     */
    private static final IntegerGuacamoleProperty DNS_PORT = new IntegerGuacamoleProperty() {
        @Override
        public String getName() {
            return "dns-resolution-port";
        }
    };

    /**
     * Property for the DNS resolution timeout in milliseconds.
     */
    private static final IntegerGuacamoleProperty DNS_TIMEOUT = new IntegerGuacamoleProperty() {
        @Override
        public String getName() {
            return "dns-resolution-timeout";
        }
    };

    /**
     * Property for the DNS cache TTL in seconds.
     */
    private static final IntegerGuacamoleProperty DNS_CACHE_TTL = new IntegerGuacamoleProperty() {
        @Override
        public String getName() {
            return "dns-resolution-cache-ttl";
        }
    };

    /**
     * Property for enabling/disabling gateway hostname resolution.
     */
    private static final BooleanGuacamoleProperty DNS_RESOLVE_GATEWAY = new BooleanGuacamoleProperty() {
        @Override
        public String getName() {
            return "dns-resolution-resolve-gateway";
        }
    };

    /**
     * Default DNS port.
     */
    public static final int DEFAULT_PORT = 53;

    /**
     * Default timeout in milliseconds for DNS resolution.
     */
    public static final int DEFAULT_TIMEOUT_MS = 5000;

    /**
     * Default cache TTL in seconds (5 minutes).
     */
    public static final int DEFAULT_CACHE_TTL_SECONDS = 300;

    /**
     * Default value for gateway hostname resolution.
     */
    public static final boolean DEFAULT_RESOLVE_GATEWAY = true;

    /**
     * Creates a new DNSConfigurationService that reads configuration from
     * environment variables first, then falls back to guacamole.properties.
     */
    public DNSConfigurationService() {
        this.environment = LocalEnvironment.getInstance();
    }

    /**
     * Creates a new DNSConfigurationService that reads configuration from
     * the provided environment. This constructor is primarily for testing.
     *
     * @param environment
     *     The environment to read configuration from.
     */
    public DNSConfigurationService(Environment environment) {
        this.environment = environment;
    }

    /**
     * Gets a string value from environment variable first, then falls back
     * to guacamole.properties.
     *
     * @param envVar
     *     The environment variable name.
     *
     * @param property
     *     The guacamole.properties property.
     *
     * @return
     *     The configured value, or null if not set.
     *
     * @throws GuacamoleException
     *     If an error occurs reading the configuration.
     */
    private String getString(String envVar, StringGuacamoleProperty property) 
            throws GuacamoleException {
        
        // Check environment variable first
        String envValue = System.getenv(envVar);
        if (envValue != null && !envValue.trim().isEmpty()) {
            LOGGER.debug("Using {} from environment variable", envVar);
            return envValue.trim();
        }

        // Fall back to properties file
        return environment.getProperty(property);
    }

    /**
     * Gets an integer value from environment variable first, then falls back
     * to guacamole.properties.
     *
     * @param envVar
     *     The environment variable name.
     *
     * @param property
     *     The guacamole.properties property.
     *
     * @param defaultValue
     *     The default value if not configured.
     *
     * @return
     *     The configured value, or the default if not set.
     *
     * @throws GuacamoleException
     *     If an error occurs reading the configuration.
     */
    private int getInteger(String envVar, IntegerGuacamoleProperty property, int defaultValue) 
            throws GuacamoleException {
        
        // Check environment variable first
        String envValue = System.getenv(envVar);
        if (envValue != null && !envValue.trim().isEmpty()) {
            try {
                int value = Integer.parseInt(envValue.trim());
                LOGGER.debug("Using {} from environment variable: {}", envVar, value);
                return value;
            } catch (NumberFormatException e) {
                LOGGER.warn("Invalid integer value '{}' for environment variable {}, using default", 
                        envValue, envVar);
            }
        }

        // Fall back to properties file
        Integer propValue = environment.getProperty(property);
        if (propValue != null) {
            return propValue;
        }

        return defaultValue;
    }

    /**
     * Gets a boolean value from environment variable first, then falls back
     * to guacamole.properties.
     *
     * @param envVar
     *     The environment variable name.
     *
     * @param property
     *     The guacamole.properties property.
     *
     * @param defaultValue
     *     The default value if not configured.
     *
     * @return
     *     The configured value, or the default if not set.
     *
     * @throws GuacamoleException
     *     If an error occurs reading the configuration.
     */
    private boolean getBoolean(String envVar, BooleanGuacamoleProperty property, boolean defaultValue) 
            throws GuacamoleException {
        
        // Check environment variable first
        String envValue = System.getenv(envVar);
        if (envValue != null && !envValue.trim().isEmpty()) {
            boolean value = "true".equalsIgnoreCase(envValue.trim()) 
                    || "1".equals(envValue.trim())
                    || "yes".equalsIgnoreCase(envValue.trim());
            LOGGER.debug("Using {} from environment variable: {}", envVar, value);
            return value;
        }

        // Fall back to properties file
        Boolean propValue = environment.getProperty(property);
        if (propValue != null) {
            return propValue;
        }

        return defaultValue;
    }

    /**
     * Returns the configured DNS server address, or null if not configured
     * (in which case system DNS should be used). The server can be an IP
     * address or a hostname (e.g., a Kubernetes service name).
     *
     * @return
     *     The DNS server address, or null to use system DNS.
     *
     * @throws GuacamoleException
     *     If an error occurs reading the configuration.
     */
    public String getDNSServer() throws GuacamoleException {
        return getString(ENV_DNS_SERVER, DNS_SERVER);
    }

    /**
     * Returns the configured DNS server port.
     *
     * @return
     *     The DNS server port.
     *
     * @throws GuacamoleException
     *     If an error occurs reading the configuration.
     */
    public int getPort() throws GuacamoleException {
        int port = getInteger(ENV_DNS_PORT, DNS_PORT, DEFAULT_PORT);
        if (port > 0 && port <= 65535) {
            return port;
        }
        LOGGER.warn("Invalid port {}, using default {}", port, DEFAULT_PORT);
        return DEFAULT_PORT;
    }

    /**
     * Returns the configured DNS resolution timeout in milliseconds.
     *
     * @return
     *     The DNS timeout in milliseconds.
     *
     * @throws GuacamoleException
     *     If an error occurs reading the configuration.
     */
    public int getTimeout() throws GuacamoleException {
        int timeout = getInteger(ENV_DNS_TIMEOUT, DNS_TIMEOUT, DEFAULT_TIMEOUT_MS);
        if (timeout > 0) {
            return timeout;
        }
        LOGGER.warn("Invalid timeout {}, using default {}", timeout, DEFAULT_TIMEOUT_MS);
        return DEFAULT_TIMEOUT_MS;
    }

    /**
     * Returns the configured DNS cache TTL in seconds.
     *
     * @return
     *     The cache TTL in seconds.
     *
     * @throws GuacamoleException
     *     If an error occurs reading the configuration.
     */
    public int getCacheTTL() throws GuacamoleException {
        int ttl = getInteger(ENV_DNS_CACHE_TTL, DNS_CACHE_TTL, DEFAULT_CACHE_TTL_SECONDS);
        if (ttl >= 0) {
            return ttl;
        }
        LOGGER.warn("Invalid cache TTL {}, using default {}", ttl, DEFAULT_CACHE_TTL_SECONDS);
        return DEFAULT_CACHE_TTL_SECONDS;
    }

    /**
     * Returns whether gateway hostnames should be resolved for RDP connections.
     *
     * @return
     *     true if gateway hostnames should be resolved, false otherwise.
     *
     * @throws GuacamoleException
     *     If an error occurs reading the configuration.
     */
    public boolean getResolveGateway() throws GuacamoleException {
        return getBoolean(ENV_DNS_RESOLVE_GATEWAY, DNS_RESOLVE_GATEWAY, DEFAULT_RESOLVE_GATEWAY);
    }

}
