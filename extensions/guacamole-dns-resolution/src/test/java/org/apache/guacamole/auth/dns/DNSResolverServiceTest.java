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
import org.apache.guacamole.auth.dns.conf.DNSConfigurationService;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Property-based tests for DNSResolverService configuration and IP address validation.
 * 
 * Feature: guacamole-dns-resolution
 */
class DNSResolverServiceTest {

    private DNSResolverService resolverService;

    @BeforeEach
    void setUp() {
        // Reset the singleton instance before each test
        DNSResolverService.resetInstance();
        // Create a fresh instance for testing
        resolverService = new DNSResolverService();
    }

    @AfterEach
    void tearDown() {
        // Reset the singleton instance after each test
        DNSResolverService.resetInstance();
    }

    // =========================================================================
    // Property 2: Invalid Configuration Fallback
    // For any invalid value in GUACAMOLE_DNS_SERVER or GUACAMOLE_DNS_TIMEOUT,
    // the DNS_Extension SHALL fall back to default behavior without throwing exceptions.
    // Validates: Requirements 1.3, 2.3
    // =========================================================================

    @Test
    void testInvalidDNSServerFallsBackToNull() {
        // Invalid DNS server addresses should result in null (system DNS)
        assertFalse(DNSResolverService.isValidIPAddress("not-an-ip"));
        assertFalse(DNSResolverService.isValidIPAddress("256.256.256.256"));
        assertFalse(DNSResolverService.isValidIPAddress("192.168.1"));
        assertFalse(DNSResolverService.isValidIPAddress(""));
        assertFalse(DNSResolverService.isValidIPAddress(null));
    }

    @Property(tries = 100)
    @Label("Property 2: Invalid strings are not valid IP addresses")
    void invalidStringsAreNotValidIPAddresses(
            @ForAll @AlphaChars @StringLength(min = 1, max = 50) String invalidAddress) {
        // Feature: guacamole-dns-resolution, Property 2: Invalid Configuration Fallback
        // Validates: Requirements 1.3, 2.3
        
        // Alpha-only strings should never be valid IP addresses
        assertFalse(DNSResolverService.isValidIPAddress(invalidAddress),
                "Alpha string '" + invalidAddress + "' should not be a valid IP address");
    }

    // =========================================================================
    // Property 3: IPv4 and IPv6 DNS Server Support
    // For any valid IPv4 or IPv6 address, the DNS_Extension SHALL accept it.
    // Validates: Requirements 1.4
    // =========================================================================

    @Property(tries = 100)
    @Label("Property 3: Valid IPv4 addresses are recognized")
    void validIPv4AddressesAreRecognized(
            @ForAll @IntRange(min = 0, max = 255) int octet1,
            @ForAll @IntRange(min = 0, max = 255) int octet2,
            @ForAll @IntRange(min = 0, max = 255) int octet3,
            @ForAll @IntRange(min = 0, max = 255) int octet4) {
        // Feature: guacamole-dns-resolution, Property 3: IPv4 and IPv6 DNS Server Support
        // Validates: Requirements 1.4
        
        String ipv4 = String.format("%d.%d.%d.%d", octet1, octet2, octet3, octet4);
        assertTrue(DNSResolverService.isIPv4Address(ipv4),
                "IPv4 address '" + ipv4 + "' should be recognized as valid");
        assertTrue(DNSResolverService.isValidIPAddress(ipv4),
                "IPv4 address '" + ipv4 + "' should be a valid IP address");
    }

    @Test
    @Label("Property 3: Common IPv6 addresses are recognized")
    void commonIPv6AddressesAreRecognized() {
        // Feature: guacamole-dns-resolution, Property 3: IPv4 and IPv6 DNS Server Support
        // Validates: Requirements 1.4
        
        // Standard IPv6 addresses
        assertTrue(DNSResolverService.isIPv6Address("2001:0db8:85a3:0000:0000:8a2e:0370:7334"));
        assertTrue(DNSResolverService.isIPv6Address("2001:db8:85a3::8a2e:370:7334"));
        assertTrue(DNSResolverService.isIPv6Address("::1"));
        assertTrue(DNSResolverService.isIPv6Address("::"));
        assertTrue(DNSResolverService.isIPv6Address("fe80::1"));
        assertTrue(DNSResolverService.isIPv6Address("2001:db8::1"));
        
        // Bracketed IPv6 (common in URLs)
        assertTrue(DNSResolverService.isIPv6Address("[::1]"));
        assertTrue(DNSResolverService.isIPv6Address("[2001:db8::1]"));
        
        // All should also pass isValidIPAddress
        assertTrue(DNSResolverService.isValidIPAddress("::1"));
        assertTrue(DNSResolverService.isValidIPAddress("2001:db8::1"));
    }

    @Property(tries = 100)
    @Label("Property 3: Generated IPv6 segments form valid addresses")
    void generatedIPv6SegmentsFormValidAddresses(
            @ForAll @IntRange(min = 0, max = 65535) int seg1,
            @ForAll @IntRange(min = 0, max = 65535) int seg2,
            @ForAll @IntRange(min = 0, max = 65535) int seg3,
            @ForAll @IntRange(min = 0, max = 65535) int seg4,
            @ForAll @IntRange(min = 0, max = 65535) int seg5,
            @ForAll @IntRange(min = 0, max = 65535) int seg6,
            @ForAll @IntRange(min = 0, max = 65535) int seg7,
            @ForAll @IntRange(min = 0, max = 65535) int seg8) {
        // Feature: guacamole-dns-resolution, Property 3: IPv4 and IPv6 DNS Server Support
        // Validates: Requirements 1.4
        
        String ipv6 = String.format("%x:%x:%x:%x:%x:%x:%x:%x",
                seg1, seg2, seg3, seg4, seg5, seg6, seg7, seg8);
        assertTrue(DNSResolverService.isIPv6Address(ipv6),
                "IPv6 address '" + ipv6 + "' should be recognized as valid");
        assertTrue(DNSResolverService.isValidIPAddress(ipv6),
                "IPv6 address '" + ipv6 + "' should be a valid IP address");
    }

    // =========================================================================
    // Property 4: Timeout Configuration
    // For any valid positive integer timeout value, the DNS_Resolver SHALL use it.
    // Validates: Requirements 2.1
    // =========================================================================

    @Test
    @Label("Property 4: Default timeout is used when not configured")
    void defaultTimeoutIsUsedWhenNotConfigured() throws GuacamoleException {
        // Feature: guacamole-dns-resolution, Property 4: Timeout Configuration
        // Validates: Requirements 2.1, 2.2
        
        resolverService.initialize();
        assertEquals(DNSConfigurationService.DEFAULT_TIMEOUT_MS, resolverService.getConfiguredTimeout(),
                "Default timeout should be " + DNSConfigurationService.DEFAULT_TIMEOUT_MS + "ms");
    }

    // =========================================================================
    // Additional unit tests for edge cases
    // =========================================================================

    @Test
    void testIPv4EdgeCases() {
        // Valid edge cases
        assertTrue(DNSResolverService.isIPv4Address("0.0.0.0"));
        assertTrue(DNSResolverService.isIPv4Address("255.255.255.255"));
        assertTrue(DNSResolverService.isIPv4Address("127.0.0.1"));
        assertTrue(DNSResolverService.isIPv4Address("192.168.1.1"));
        
        // Invalid cases
        assertFalse(DNSResolverService.isIPv4Address("256.0.0.0"));
        assertFalse(DNSResolverService.isIPv4Address("192.168.1"));
        assertFalse(DNSResolverService.isIPv4Address("192.168.1.1.1"));
        assertFalse(DNSResolverService.isIPv4Address("192.168.1."));
        assertFalse(DNSResolverService.isIPv4Address(".192.168.1.1"));
        assertFalse(DNSResolverService.isIPv4Address("192.168.1.1a"));
    }

    @Test
    void testIPv6EdgeCases() {
        // Invalid cases
        assertFalse(DNSResolverService.isIPv6Address(""));
        assertFalse(DNSResolverService.isIPv6Address(null));
        assertFalse(DNSResolverService.isIPv6Address("192.168.1.1")); // IPv4 is not IPv6
        assertFalse(DNSResolverService.isIPv6Address("not-an-ipv6"));
    }

    @Test
    void testIsIPAddressDistinguishesTypes() {
        // IPv4
        assertTrue(DNSResolverService.isIPAddress("192.168.1.1"));
        assertTrue(DNSResolverService.isIPv4Address("192.168.1.1"));
        assertFalse(DNSResolverService.isIPv6Address("192.168.1.1"));
        
        // IPv6
        assertTrue(DNSResolverService.isIPAddress("::1"));
        assertFalse(DNSResolverService.isIPv4Address("::1"));
        assertTrue(DNSResolverService.isIPv6Address("::1"));
        
        // Hostname
        assertFalse(DNSResolverService.isIPAddress("example.com"));
        assertFalse(DNSResolverService.isIPv4Address("example.com"));
        assertFalse(DNSResolverService.isIPv6Address("example.com"));
    }

    @Test
    void testInitializeIsIdempotent() throws GuacamoleException {
        // Multiple calls to initialize should not cause issues
        resolverService.initialize();
        int timeout1 = resolverService.getConfiguredTimeout();
        
        resolverService.initialize();
        int timeout2 = resolverService.getConfiguredTimeout();
        
        assertEquals(timeout1, timeout2, "Multiple initializations should return same timeout");
    }

}
