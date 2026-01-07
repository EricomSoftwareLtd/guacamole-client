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
import org.apache.guacamole.net.auth.Connection;
import org.apache.guacamole.net.auth.DecoratingDirectory;
import org.apache.guacamole.net.auth.DelegatingUserContext;
import org.apache.guacamole.net.auth.Directory;
import org.apache.guacamole.net.auth.UserContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A UserContext implementation that wraps another UserContext and provides
 * DNS resolution capability for all connections. Connections retrieved from
 * this context will have their hostnames resolved using the configured DNS
 * server when connecting.
 */
public class DNSResolvingUserContext extends DelegatingUserContext {

    /**
     * Logger for this class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(DNSResolvingUserContext.class);

    /**
     * Creates a new DNSResolvingUserContext which wraps the given UserContext,
     * providing DNS resolution capability for all connections.
     *
     * @param userContext
     *     The UserContext to wrap.
     */
    public DNSResolvingUserContext(UserContext userContext) {
        super(userContext);
        LOGGER.debug("DNS resolution enabled for user context");
    }

    /**
     * Returns the underlying UserContext wrapped by this DNSResolvingUserContext.
     *
     * @return
     *     The wrapped UserContext.
     */
    public UserContext getUndecorated() {
        return getDelegateUserContext();
    }

    @Override
    public Directory<Connection> getConnectionDirectory() throws GuacamoleException {
        return new DecoratingDirectory<Connection>(super.getConnectionDirectory()) {

            @Override
            protected Connection decorate(Connection object) throws GuacamoleException {
                return new DNSResolvingConnection(object);
            }

            @Override
            protected Connection undecorate(Connection object) throws GuacamoleException {
                if (object instanceof DNSResolvingConnection) {
                    return ((DNSResolvingConnection) object).getUndecorated();
                }
                return object;
            }

        };
    }

}
