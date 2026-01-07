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

import net.jqwik.api.*;
import net.jqwik.api.constraints.*;
import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.net.auth.AuthenticatedUser;
import org.apache.guacamole.net.auth.Credentials;
import org.apache.guacamole.net.auth.UserContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Property-based tests for DNSResolutionAuthenticationProvider.
 * 
 * Feature: guacamole-dns-resolution
 */
@ExtendWith(MockitoExtension.class)
class DNSResolutionAuthenticationProviderTest {

    @Mock
    private UserContext mockUserContext;

    @Mock
    private AuthenticatedUser mockAuthenticatedUser;

    @Mock
    private Credentials mockCredentials;

    private DNSResolutionAuthenticationProvider provider;

    @BeforeEach
    void setUp() {
        DNSResolverService.resetInstance();
        provider = new DNSResolutionAuthenticationProvider();
    }

    @AfterEach
    void tearDown() {
        DNSResolverService.resetInstance();
    }

    // =========================================================================
    // Property 9: Authentication Passthrough
    // For any authentication or authorization decision made by other extensions,
    // the DNS_Extension SHALL not modify or interfere with that decision.
    // Validates: Requirements 5.3
    // =========================================================================

    @Test
    @Label("Property 9: Provider identifier is correct")
    void providerIdentifierIsCorrect() {
        // Feature: guacamole-dns-resolution, Property 9: Authentication Passthrough
        // Validates: Requirements 5.1
        
        assertEquals("dns-resolution", provider.getIdentifier(),
                "Provider identifier should be 'dns-resolution'");
    }

    @Test
    @Label("Property 9: Decorate returns DNSResolvingUserContext")
    void decorateReturnsDNSResolvingUserContext() throws GuacamoleException {
        // Feature: guacamole-dns-resolution, Property 9: Authentication Passthrough
        // Validates: Requirements 5.1, 5.2
        
        when(mockAuthenticatedUser.getIdentifier()).thenReturn("testuser");
        
        UserContext decorated = provider.decorate(mockUserContext, mockAuthenticatedUser, mockCredentials);
        
        assertNotNull(decorated);
        assertTrue(decorated instanceof DNSResolvingUserContext,
                "Decorated context should be DNSResolvingUserContext");
    }

    @Test
    @Label("Property 9: Decorate preserves original context")
    void decoratePreservesOriginalContext() throws GuacamoleException {
        // Feature: guacamole-dns-resolution, Property 9: Authentication Passthrough
        // Validates: Requirements 5.3
        
        when(mockAuthenticatedUser.getIdentifier()).thenReturn("testuser");
        
        UserContext decorated = provider.decorate(mockUserContext, mockAuthenticatedUser, mockCredentials);
        
        assertTrue(decorated instanceof DNSResolvingUserContext);
        DNSResolvingUserContext dnsContext = (DNSResolvingUserContext) decorated;
        
        assertSame(mockUserContext, dnsContext.getUndecorated(),
                "Original UserContext should be preserved inside decorated context");
    }

    @Test
    @Label("Property 9: AuthenticateUser returns null (no interference)")
    void authenticateUserReturnsNull() throws GuacamoleException {
        // Feature: guacamole-dns-resolution, Property 9: Authentication Passthrough
        // Validates: Requirements 5.3
        
        // The provider should not perform authentication itself
        AuthenticatedUser result = provider.authenticateUser(mockCredentials);
        
        assertNull(result, "authenticateUser should return null (no authentication)");
    }

    @Test
    @Label("Property 9: GetUserContext returns null (no interference)")
    void getUserContextReturnsNull() throws GuacamoleException {
        // Feature: guacamole-dns-resolution, Property 9: Authentication Passthrough
        // Validates: Requirements 5.3
        
        // The provider should not provide its own UserContext
        UserContext result = provider.getUserContext(mockAuthenticatedUser);
        
        assertNull(result, "getUserContext should return null (no own context)");
    }

    @Test
    @Label("Property 9: UpdateAuthenticatedUser passes through unchanged")
    void updateAuthenticatedUserPassesThrough() throws GuacamoleException {
        // Feature: guacamole-dns-resolution, Property 9: Authentication Passthrough
        // Validates: Requirements 5.3
        
        AuthenticatedUser result = provider.updateAuthenticatedUser(mockAuthenticatedUser, mockCredentials);
        
        assertSame(mockAuthenticatedUser, result,
                "updateAuthenticatedUser should return the same user unchanged");
    }

    @Test
    @Label("Property 9: UpdateUserContext passes through unchanged")
    void updateUserContextPassesThrough() throws GuacamoleException {
        // Feature: guacamole-dns-resolution, Property 9: Authentication Passthrough
        // Validates: Requirements 5.3
        
        UserContext result = provider.updateUserContext(mockUserContext, mockAuthenticatedUser, mockCredentials);
        
        assertSame(mockUserContext, result,
                "updateUserContext should return the same context unchanged");
    }

    @Property(tries = 100)
    @Label("Property 9: Decorate works for any user identifier")
    void decorateWorksForAnyUserIdentifier(
            @ForAll @AlphaChars @StringLength(min = 1, max = 50) String username) throws GuacamoleException {
        // Feature: guacamole-dns-resolution, Property 9: Authentication Passthrough
        // Validates: Requirements 5.2, 5.3
        
        when(mockAuthenticatedUser.getIdentifier()).thenReturn(username);
        
        UserContext decorated = provider.decorate(mockUserContext, mockAuthenticatedUser, mockCredentials);
        
        assertNotNull(decorated, "Decorate should work for any username");
        assertTrue(decorated instanceof DNSResolvingUserContext,
                "Result should be DNSResolvingUserContext for any username");
    }

    @Test
    @Label("Property 9: Redecorate creates new decorated context")
    void redecorateCreatesNewDecoratedContext() throws GuacamoleException {
        // Feature: guacamole-dns-resolution, Property 9: Authentication Passthrough
        // Validates: Requirements 5.2
        
        when(mockAuthenticatedUser.getIdentifier()).thenReturn("testuser");
        
        UserContext firstDecorated = provider.decorate(mockUserContext, mockAuthenticatedUser, mockCredentials);
        
        // Create a new mock for the updated context
        UserContext updatedContext = mock(UserContext.class);
        
        UserContext redecorated = provider.redecorate(firstDecorated, updatedContext, 
                mockAuthenticatedUser, mockCredentials);
        
        assertNotNull(redecorated);
        assertTrue(redecorated instanceof DNSResolvingUserContext);
        
        // The redecorated context should wrap the updated context, not the original
        DNSResolvingUserContext dnsContext = (DNSResolvingUserContext) redecorated;
        assertSame(updatedContext, dnsContext.getUndecorated(),
                "Redecorated context should wrap the updated context");
    }

    @Test
    @Label("Property 9: Multiple decorations are independent")
    void multipleDecorationsAreIndependent() throws GuacamoleException {
        // Feature: guacamole-dns-resolution, Property 9: Authentication Passthrough
        // Validates: Requirements 5.2
        
        when(mockAuthenticatedUser.getIdentifier()).thenReturn("testuser");
        
        UserContext context1 = mock(UserContext.class);
        UserContext context2 = mock(UserContext.class);
        
        UserContext decorated1 = provider.decorate(context1, mockAuthenticatedUser, mockCredentials);
        UserContext decorated2 = provider.decorate(context2, mockAuthenticatedUser, mockCredentials);
        
        assertNotSame(decorated1, decorated2, "Each decoration should create a new instance");
        
        DNSResolvingUserContext dns1 = (DNSResolvingUserContext) decorated1;
        DNSResolvingUserContext dns2 = (DNSResolvingUserContext) decorated2;
        
        assertSame(context1, dns1.getUndecorated());
        assertSame(context2, dns2.getUndecorated());
    }

}
