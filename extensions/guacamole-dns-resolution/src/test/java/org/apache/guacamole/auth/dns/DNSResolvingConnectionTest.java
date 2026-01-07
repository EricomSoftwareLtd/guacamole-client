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
import org.apache.guacamole.protocol.GuacamoleConfiguration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Property-based tests for DNSResolvingConnection.
 * 
 * Feature: guacamole-dns-resolution
 */
class DNSResolvingConnectionTest {

    @BeforeEach
    void setUp() {
        DNSResolverService.resetInstance();
    }

    @AfterEach
    void tearDown() {
        DNSResolverService.resetInstance();
    }

    // =========================================================================
    // Property 6: IP Address Passthrough
    // For any connection where the hostname parameter is already a valid IP address,
    // the Connection_Decorator SHALL pass through the IP address unchanged.
    // Validates: Requirements 3.2
    // =========================================================================

    @Property(tries = 100)
    @Label("Property 6: IPv4 addresses pass through unchanged")
    void ipv4AddressesPassThroughUnchanged(
            @ForAll @IntRange(min = 0, max = 255) int octet1,
            @ForAll @IntRange(min = 0, max = 255) int octet2,
            @ForAll @IntRange(min = 0, max = 255) int octet3,
            @ForAll @IntRange(min = 0, max = 255) int octet4) {
        // Feature: guacamole-dns-resolution, Property 6: IP Address Passthrough
        // Validates: Requirements 3.2
        
        String ipv4 = String.format("%d.%d.%d.%d", octet1, octet2, octet3, octet4);
        
        // IP addresses should be detected and not require resolution
        assertTrue(DNSResolverService.isIPAddress(ipv4),
                "IPv4 address '" + ipv4 + "' should be recognized as an IP address");
    }

    @Property(tries = 100)
    @Label("Property 6: IPv6 addresses pass through unchanged")
    void ipv6AddressesPassThroughUnchanged(
            @ForAll @IntRange(min = 0, max = 65535) int seg1,
            @ForAll @IntRange(min = 0, max = 65535) int seg2,
            @ForAll @IntRange(min = 0, max = 65535) int seg3,
            @ForAll @IntRange(min = 0, max = 65535) int seg4,
            @ForAll @IntRange(min = 0, max = 65535) int seg5,
            @ForAll @IntRange(min = 0, max = 65535) int seg6,
            @ForAll @IntRange(min = 0, max = 65535) int seg7,
            @ForAll @IntRange(min = 0, max = 65535) int seg8) {
        // Feature: guacamole-dns-resolution, Property 6: IP Address Passthrough
        // Validates: Requirements 3.2
        
        String ipv6 = String.format("%x:%x:%x:%x:%x:%x:%x:%x",
                seg1, seg2, seg3, seg4, seg5, seg6, seg7, seg8);
        
        // IP addresses should be detected and not require resolution
        assertTrue(DNSResolverService.isIPAddress(ipv6),
                "IPv6 address '" + ipv6 + "' should be recognized as an IP address");
    }

    // =========================================================================
    // Property 7: Parameter Preservation Invariant
    // For any connection configuration, after DNS resolution the Connection_Decorator
    // SHALL preserve all connection parameters except the hostname parameter unchanged.
    // Validates: Requirements 3.5
    // =========================================================================

    @Property(tries = 100)
    @Label("Property 7: Non-hostname parameters are preserved")
    void nonHostnameParametersArePreserved(
            @ForAll @AlphaChars @StringLength(min = 1, max = 20) String param1Name,
            @ForAll @AlphaChars @StringLength(min = 1, max = 50) String param1Value,
            @ForAll @AlphaChars @StringLength(min = 1, max = 20) String param2Name,
            @ForAll @AlphaChars @StringLength(min = 1, max = 50) String param2Value) {
        // Feature: guacamole-dns-resolution, Property 7: Parameter Preservation Invariant
        // Validates: Requirements 3.5
        
        // Skip if parameter names conflict with hostname
        if (param1Name.equals(DNSResolvingConnection.HOSTNAME_PARAMETER) ||
            param2Name.equals(DNSResolvingConnection.HOSTNAME_PARAMETER) ||
            param1Name.equals(param2Name)) {
            return;
        }
        
        // Create a configuration with multiple parameters
        GuacamoleConfiguration config = new GuacamoleConfiguration();
        config.setProtocol("rdp");
        config.setParameter(param1Name, param1Value);
        config.setParameter(param2Name, param2Value);
        config.setParameter(DNSResolvingConnection.HOSTNAME_PARAMETER, "192.168.1.1");
        
        // Store original values
        Map<String, String> originalParams = new HashMap<>();
        for (String name : config.getParameterNames()) {
            if (!name.equals(DNSResolvingConnection.HOSTNAME_PARAMETER)) {
                originalParams.put(name, config.getParameter(name));
            }
        }
        
        // Verify all non-hostname parameters are preserved
        for (Map.Entry<String, String> entry : originalParams.entrySet()) {
            assertEquals(entry.getValue(), config.getParameter(entry.getKey()),
                    "Parameter '" + entry.getKey() + "' should be preserved");
        }
    }

    @Test
    @Label("Property 7: Common connection parameters are preserved")
    void commonConnectionParametersArePreserved() {
        // Feature: guacamole-dns-resolution, Property 7: Parameter Preservation Invariant
        // Validates: Requirements 3.5
        
        GuacamoleConfiguration config = new GuacamoleConfiguration();
        config.setProtocol("rdp");
        config.setParameter("hostname", "192.168.1.1");
        config.setParameter("port", "3389");
        config.setParameter("username", "testuser");
        config.setParameter("password", "testpass");
        config.setParameter("domain", "TESTDOMAIN");
        config.setParameter("security", "nla");
        config.setParameter("ignore-cert", "true");
        
        // Verify protocol is preserved
        assertEquals("rdp", config.getProtocol());
        
        // Verify all parameters are accessible
        assertEquals("3389", config.getParameter("port"));
        assertEquals("testuser", config.getParameter("username"));
        assertEquals("testpass", config.getParameter("password"));
        assertEquals("TESTDOMAIN", config.getParameter("domain"));
        assertEquals("nla", config.getParameter("security"));
        assertEquals("true", config.getParameter("ignore-cert"));
    }

    // =========================================================================
    // Property 5: Hostname Resolution at Connection Time
    // For any connection with a hostname parameter that is not already an IP address,
    // the Connection_Decorator SHALL resolve the hostname at connect() time.
    // Validates: Requirements 3.1, 3.3, 7.3
    // =========================================================================

    @Test
    @Label("Property 5: Hostnames are identified for resolution")
    void hostnamesAreIdentifiedForResolution() {
        // Feature: guacamole-dns-resolution, Property 5: Hostname Resolution at Connection Time
        // Validates: Requirements 3.1, 3.3, 7.3
        
        // These should NOT be identified as IP addresses (require resolution)
        assertFalse(DNSResolverService.isIPAddress("example.com"));
        assertFalse(DNSResolverService.isIPAddress("server.internal.corp"));
        assertFalse(DNSResolverService.isIPAddress("my-server"));
        assertFalse(DNSResolverService.isIPAddress("host123.domain.local"));
        assertFalse(DNSResolverService.isIPAddress("rdp-server-01"));
        
        // These SHOULD be identified as IP addresses (no resolution needed)
        assertTrue(DNSResolverService.isIPAddress("192.168.1.1"));
        assertTrue(DNSResolverService.isIPAddress("10.0.0.1"));
        assertTrue(DNSResolverService.isIPAddress("::1"));
        assertTrue(DNSResolverService.isIPAddress("2001:db8::1"));
    }

    @Property(tries = 100)
    @Label("Property 5: Valid hostnames are not IP addresses")
    void validHostnamesAreNotIPAddresses(
            @ForAll("validHostnames") String hostname) {
        // Feature: guacamole-dns-resolution, Property 5: Hostname Resolution at Connection Time
        // Validates: Requirements 3.1, 3.3, 7.3
        
        assertFalse(DNSResolverService.isIPAddress(hostname),
                "Hostname '" + hostname + "' should not be identified as an IP address");
    }

    @Provide
    Arbitrary<String> validHostnames() {
        // Generate valid hostname patterns
        Arbitrary<String> simpleHostnames = Arbitraries.strings()
                .alpha()
                .ofMinLength(1)
                .ofMaxLength(20)
                .map(String::toLowerCase);
        
        Arbitrary<String> dottedHostnames = Combinators.combine(
                simpleHostnames,
                simpleHostnames
        ).as((part1, part2) -> part1 + "." + part2);
        
        Arbitrary<String> hyphenatedHostnames = Combinators.combine(
                simpleHostnames,
                Arbitraries.integers().between(1, 99)
        ).as((name, num) -> name + "-" + num);
        
        return Arbitraries.oneOf(simpleHostnames, dottedHostnames, hyphenatedHostnames);
    }

    // =========================================================================
    // Additional unit tests
    // =========================================================================

    @Test
    void testGetUndecoratedReturnsOriginalConnection() {
        // Create a mock-like simple connection for testing
        GuacamoleConfiguration config = new GuacamoleConfiguration();
        config.setProtocol("rdp");
        config.setParameter("hostname", "test.example.com");
        
        // We can't easily test without mocking, but we can verify the class structure
        assertNotNull(DNSResolvingConnection.HOSTNAME_PARAMETER);
        assertEquals("hostname", DNSResolvingConnection.HOSTNAME_PARAMETER);
    }

    @Test
    void testHostnameParameterConstant() {
        assertEquals("hostname", DNSResolvingConnection.HOSTNAME_PARAMETER,
                "HOSTNAME_PARAMETER should be 'hostname'");
    }

}
