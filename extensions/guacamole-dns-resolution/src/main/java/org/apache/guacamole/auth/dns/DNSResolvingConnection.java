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

package org.apache.guacamole.auth.dns;

import java.util.Map;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.GuacamoleTunnel;
import org.apache.guacamole.net.auth.Connection;
import org.apache.guacamole.net.auth.DelegatingConnection;
import org.apache.guacamole.protocol.GuacamoleClientInformation;
import org.apache.guacamole.protocol.GuacamoleConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A Connection implementation that wraps another connection and performs
 * DNS resolution on hostname parameters before establishing the connection.
 * This allows hostnames to be resolved using a custom DNS server configured
 * via guacamole.properties.
 * 
 * <p>This implementation resolves the following parameters:</p>
 * <ul>
 *   <li>hostname - The main connection hostname (all protocols)</li>
 *   <li>gateway-hostname - The RDP gateway hostname (RDP only, if enabled)</li>
 * </ul>
 * 
 * <p>The configuration is copied before modification to ensure thread-safety
 * when the same connection object is used concurrently.</p>
 */
public class DNSResolvingConnection extends DelegatingConnection {

    /**
     * Logger for this class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(DNSResolvingConnection.class);

    /**
     * The parameter name for the hostname in Guacamole connection configurations.
     * This is used by RDP, VNC, SSH, Telnet, and Kubernetes protocols.
     */
    public static final String HOSTNAME_PARAMETER = "hostname";

    /**
     * The parameter name for the RDP gateway hostname.
     */
    public static final String GATEWAY_HOSTNAME_PARAMETER = "gateway-hostname";

    /**
     * The protocol name for RDP connections.
     */
    private static final String RDP_PROTOCOL = "rdp";

    /**
     * The DNS resolver service to use for resolution.
     */
    private final DNSResolverService resolverService;

    /**
     * Wraps the given Connection object, providing DNS resolution capability
     * for hostname parameters when connecting.
     *
     * @param connection
     *     The Connection object to wrap.
     */
    public DNSResolvingConnection(Connection connection) {
        this(connection, DNSResolverService.getInstance());
    }

    /**
     * Wraps the given Connection object, providing DNS resolution capability
     * for hostname parameters when connecting. This constructor allows
     * injection of a custom resolver service for testing.
     *
     * @param connection
     *     The Connection object to wrap.
     *
     * @param resolverService
     *     The DNS resolver service to use.
     */
    public DNSResolvingConnection(Connection connection, DNSResolverService resolverService) {
        super(connection);
        this.resolverService = resolverService;
    }

    /**
     * Returns the original Connection object wrapped by this DNSResolvingConnection.
     *
     * @return
     *     The wrapped Connection object.
     */
    public Connection getUndecorated() {
        return getDelegateConnection();
    }

    @Override
    public GuacamoleTunnel connect(GuacamoleClientInformation info,
            Map<String, String> tokens) throws GuacamoleException {

        // Get the current configuration
        GuacamoleConfiguration originalConfig = getConfiguration();
        
        if (originalConfig != null) {
            // Create a copy of the configuration to avoid modifying the original
            // This ensures thread-safety when the same connection is used concurrently
            GuacamoleConfiguration config = new GuacamoleConfiguration(originalConfig);
            boolean modified = false;

            // Resolve the main hostname parameter
            modified |= resolveHostnameParameter(config, HOSTNAME_PARAMETER, "hostname");

            // Resolve gateway hostname for RDP connections (if enabled)
            String protocol = config.getProtocol();
            if (RDP_PROTOCOL.equals(protocol) && resolverService.shouldResolveGateway()) {
                modified |= resolveHostnameParameter(config, GATEWAY_HOSTNAME_PARAMETER, "gateway hostname");
            }

            // Only update the configuration if we made changes
            if (modified) {
                // Set the modified configuration on the delegate connection
                getDelegateConnection().setConfiguration(config);
            }
        }

        // Proceed with the connection
        return super.connect(info, tokens);
    }

    /**
     * Resolves a hostname parameter in the given configuration if it contains
     * a hostname (not an IP address).
     *
     * @param config
     *     The configuration to modify.
     *
     * @param parameterName
     *     The name of the parameter to resolve.
     *
     * @param description
     *     A human-readable description of the parameter for logging.
     *
     * @return
     *     true if the configuration was modified, false otherwise.
     *
     * @throws GuacamoleException
     *     If DNS resolution fails.
     */
    private boolean resolveHostnameParameter(GuacamoleConfiguration config,
            String parameterName, String description) throws GuacamoleException {

        String hostname = config.getParameter(parameterName);
        
        if (hostname == null || hostname.trim().isEmpty()) {
            LOGGER.debug("Connection '{}': No {} parameter found, skipping DNS resolution",
                    getIdentifier(), description);
            return false;
        }

        hostname = hostname.trim();

        // Only resolve if it's not already an IP address
        if (DNSResolverService.isIPAddress(hostname)) {
            LOGGER.debug("Connection '{}': {} '{}' is already an IP address, skipping resolution",
                    getIdentifier(), description, hostname);
            return false;
        }

        LOGGER.debug("Connection '{}': Resolving {} '{}'",
                getIdentifier(), description, hostname);

        try {
            String resolvedIP = resolverService.resolve(hostname);
            
            // Update the configuration with the resolved IP
            config.setParameter(parameterName, resolvedIP);
            
            LOGGER.info("Connection '{}': Resolved {} '{}' to '{}'",
                    getIdentifier(), description, hostname, resolvedIP);
            return true;
        }
        catch (GuacamoleException e) {
            LOGGER.error("Connection '{}': Failed to resolve {} '{}': {}",
                    getIdentifier(), description, hostname, e.getMessage());
            throw e;
        }
    }

}
