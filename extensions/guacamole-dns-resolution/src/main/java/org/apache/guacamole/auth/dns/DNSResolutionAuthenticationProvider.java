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

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.auth.AbstractAuthenticationProvider;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.net.auth.UserContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * AuthenticationProvider implementation that provides DNS resolution capability
 * for connection hostnames. This provider decorates UserContexts from other
 * authentication providers, wrapping their connections with DNS resolution
 * functionality.
 * 
 * <p>This provider does not perform any authentication itself - it only decorates
 * existing UserContexts to add DNS resolution capability. Authentication decisions
 * are passed through unchanged from other providers.</p>
 * 
 * <p>Configuration is done via guacamole.properties:</p>
 * <ul>
 *   <li>dns-resolution-server - IP address of the DNS server to use</li>
 *   <li>dns-resolution-timeout - Timeout in milliseconds (default: 5000)</li>
 *   <li>dns-resolution-cache-ttl - Cache TTL in seconds (default: 300)</li>
 *   <li>dns-resolution-resolve-gateway - Whether to resolve RDP gateway hostnames (default: true)</li>
 * </ul>
 */
public class DNSResolutionAuthenticationProvider extends AbstractAuthenticationProvider {

    /**
     * Logger for this class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(DNSResolutionAuthenticationProvider.class);

    /**
     * The unique identifier for this authentication provider.
     */
    private static final String IDENTIFIER = "dns-resolution";

    /**
     * Creates a new DNSResolutionAuthenticationProvider. The DNS resolver service
     * will be initialized lazily when first needed.
     */
    public DNSResolutionAuthenticationProvider() {
        LOGGER.info("DNS Resolution extension loaded");
    }

    @Override
    public String getIdentifier() {
        return IDENTIFIER;
    }

    /**
     * Decorates the given UserContext with DNS resolution capability. The
     * decorated context will resolve hostnames in connection configurations
     * using the configured DNS server (or system DNS if not configured).
     * 
     * <p>This method does not interfere with authentication or authorization
     * decisions - it only adds DNS resolution functionality to connections.</p>
     *
     * @param context
     *     The UserContext to decorate.
     *
     * @param authenticatedUser
     *     The AuthenticatedUser associated with the UserContext.
     *
     * @param credentials
     *     The Credentials used to authenticate the user.
     *
     * @return
     *     A DNSResolvingUserContext wrapping the provided context.
     *
     * @throws GuacamoleException
     *     If an error occurs during decoration.
     */
    @Override
    public UserContext decorate(UserContext context,
            AuthenticatedUser authenticatedUser, Credentials credentials)
            throws GuacamoleException {

        LOGGER.debug("Decorating UserContext for user '{}' with DNS resolution capability",
                authenticatedUser.getIdentifier());

        // Initialize the DNS resolver service (lazy initialization)
        DNSResolverService.getInstance().initialize();

        // Wrap the context with DNS resolution capability
        return new DNSResolvingUserContext(context);
    }

    /**
     * Re-decorates the given UserContext. This implementation simply calls
     * decorate() to create a new decorated context, as the DNS resolution
     * decoration is stateless.
     *
     * @param decorated
     *     The previously decorated UserContext.
     *
     * @param context
     *     The updated UserContext to decorate.
     *
     * @param authenticatedUser
     *     The AuthenticatedUser associated with the UserContext.
     *
     * @param credentials
     *     The Credentials used to authenticate the user.
     *
     * @return
     *     A new DNSResolvingUserContext wrapping the updated context.
     *
     * @throws GuacamoleException
     *     If an error occurs during re-decoration.
     */
    @Override
    public UserContext redecorate(UserContext decorated, UserContext context,
            AuthenticatedUser authenticatedUser, Credentials credentials)
            throws GuacamoleException {

        // DNS resolution decoration is stateless, so we can simply create a new one
        return decorate(context, authenticatedUser, credentials);
    }

}
