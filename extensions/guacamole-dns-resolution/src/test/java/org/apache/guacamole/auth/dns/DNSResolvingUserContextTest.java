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
import org.apache.guacamole.net.auth.Directory;
import org.apache.guacamole.net.auth.UserContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for DNSResolvingUserContext.
 * 
 * Feature: guacamole-dns-resolution
 * Validates: Requirements 5.2
 */
@ExtendWith(MockitoExtension.class)
class DNSResolvingUserContextTest {

    @Mock
    private UserContext mockUserContext;

    @Mock
    private Directory<Connection> mockConnectionDirectory;

    @Mock
    private Connection mockConnection;

    @BeforeEach
    void setUp() {
        DNSResolverService.resetInstance();
    }

    @AfterEach
    void tearDown() {
        DNSResolverService.resetInstance();
    }

    @Test
    void testConstructorWrapsUserContext() {
        DNSResolvingUserContext context = new DNSResolvingUserContext(mockUserContext);
        
        assertNotNull(context);
        assertEquals(mockUserContext, context.getUndecorated());
    }

    @Test
    void testGetUndecoratedReturnsOriginalContext() {
        DNSResolvingUserContext context = new DNSResolvingUserContext(mockUserContext);
        
        UserContext undecorated = context.getUndecorated();
        
        assertSame(mockUserContext, undecorated,
                "getUndecorated() should return the original UserContext");
    }

    @Test
    void testGetConnectionDirectoryReturnsDecoratingDirectory() throws GuacamoleException {
        when(mockUserContext.getConnectionDirectory()).thenReturn(mockConnectionDirectory);
        
        DNSResolvingUserContext context = new DNSResolvingUserContext(mockUserContext);
        Directory<Connection> directory = context.getConnectionDirectory();
        
        assertNotNull(directory);
        // The directory should be a DecoratingDirectory, not the original
        assertNotSame(mockConnectionDirectory, directory);
    }

    @Test
    void testConnectionsAreDecoratedWhenRetrieved() throws GuacamoleException {
        when(mockUserContext.getConnectionDirectory()).thenReturn(mockConnectionDirectory);
        when(mockConnectionDirectory.get("test-connection")).thenReturn(mockConnection);
        when(mockConnection.getIdentifier()).thenReturn("test-connection");
        
        DNSResolvingUserContext context = new DNSResolvingUserContext(mockUserContext);
        Directory<Connection> directory = context.getConnectionDirectory();
        Connection connection = directory.get("test-connection");
        
        assertNotNull(connection);
        assertTrue(connection instanceof DNSResolvingConnection,
                "Retrieved connection should be wrapped in DNSResolvingConnection");
    }

    @Test
    void testDecoratedConnectionCanBeUndecorated() throws GuacamoleException {
        when(mockUserContext.getConnectionDirectory()).thenReturn(mockConnectionDirectory);
        when(mockConnectionDirectory.get("test-connection")).thenReturn(mockConnection);
        when(mockConnection.getIdentifier()).thenReturn("test-connection");
        
        DNSResolvingUserContext context = new DNSResolvingUserContext(mockUserContext);
        Directory<Connection> directory = context.getConnectionDirectory();
        Connection decoratedConnection = directory.get("test-connection");
        
        assertTrue(decoratedConnection instanceof DNSResolvingConnection);
        DNSResolvingConnection dnsConnection = (DNSResolvingConnection) decoratedConnection;
        Connection undecorated = dnsConnection.getUndecorated();
        
        assertSame(mockConnection, undecorated,
                "Undecorated connection should be the original mock connection");
    }

    @Test
    void testGetAllConnectionsAreDecorated() throws GuacamoleException {
        Connection mockConnection2 = mock(Connection.class);
        when(mockConnection.getIdentifier()).thenReturn("conn1");
        when(mockConnection2.getIdentifier()).thenReturn("conn2");
        
        when(mockUserContext.getConnectionDirectory()).thenReturn(mockConnectionDirectory);
        when(mockConnectionDirectory.getAll(Arrays.asList("conn1", "conn2")))
                .thenReturn(Arrays.asList(mockConnection, mockConnection2));
        
        DNSResolvingUserContext context = new DNSResolvingUserContext(mockUserContext);
        Directory<Connection> directory = context.getConnectionDirectory();
        Collection<Connection> connections = directory.getAll(Arrays.asList("conn1", "conn2"));
        
        assertEquals(2, connections.size());
        for (Connection conn : connections) {
            assertTrue(conn instanceof DNSResolvingConnection,
                    "All retrieved connections should be wrapped in DNSResolvingConnection");
        }
    }

    @Test
    void testNullConnectionReturnsNull() throws GuacamoleException {
        when(mockUserContext.getConnectionDirectory()).thenReturn(mockConnectionDirectory);
        when(mockConnectionDirectory.get("nonexistent")).thenReturn(null);
        
        DNSResolvingUserContext context = new DNSResolvingUserContext(mockUserContext);
        Directory<Connection> directory = context.getConnectionDirectory();
        Connection connection = directory.get("nonexistent");
        
        assertNull(connection, "Non-existent connection should return null");
    }

    @Test
    void testEmptyCollectionReturnsEmptyCollection() throws GuacamoleException {
        when(mockUserContext.getConnectionDirectory()).thenReturn(mockConnectionDirectory);
        when(mockConnectionDirectory.getAll(Collections.emptyList()))
                .thenReturn(Collections.emptyList());
        
        DNSResolvingUserContext context = new DNSResolvingUserContext(mockUserContext);
        Directory<Connection> directory = context.getConnectionDirectory();
        Collection<Connection> connections = directory.getAll(Collections.emptyList());
        
        assertNotNull(connections);
        assertTrue(connections.isEmpty(), "Empty request should return empty collection");
    }

    @Test
    void testGetIdentifiersPassesThrough() throws GuacamoleException {
        when(mockUserContext.getConnectionDirectory()).thenReturn(mockConnectionDirectory);
        when(mockConnectionDirectory.getIdentifiers())
                .thenReturn(Arrays.asList("conn1", "conn2", "conn3"));
        
        DNSResolvingUserContext context = new DNSResolvingUserContext(mockUserContext);
        Directory<Connection> directory = context.getConnectionDirectory();
        Collection<String> identifiers = directory.getIdentifiers();
        
        assertEquals(3, identifiers.size());
        assertTrue(identifiers.contains("conn1"));
        assertTrue(identifiers.contains("conn2"));
        assertTrue(identifiers.contains("conn3"));
    }

}
