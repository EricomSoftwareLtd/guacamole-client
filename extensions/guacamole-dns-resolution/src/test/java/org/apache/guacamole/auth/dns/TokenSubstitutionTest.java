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

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for token substitution compatibility in DNS resolution.
 * 
 * Feature: guacamole-dns-resolution
 * Property 10: Token Substitution Compatibility
 * Validates: Requirements 7.4
 */
class TokenSubstitutionTest {

    @BeforeEach
    void setUp() {
        DNSResolverService.resetInstance();
    }

    @AfterEach
    void tearDown() {
        DNSResolverService.resetInstance();
    }

    // =========================================================================
    // Property 10: Token Substitution Compatibility
    // For any hostname parameter containing token placeholders that have been
    // substituted, the DNS_Extension SHALL resolve the resulting hostname correctly.
    // Validates: Requirements 7.4
    // =========================================================================

    @Test
    @Label("Property 10: Substituted hostname is recognized as hostname")
    void substitutedHostnameIsRecognizedAsHostname() {
        // Feature: guacamole-dns-resolution, Property 10: Token Substitution Compatibility
        // Validates: Requirements 7.4
        
        // Simulate a hostname that was created via token substitution
        // e.g., ${GUAC_USERNAME}-workstation.internal.corp -> john-workstation.internal.corp
        String substitutedHostname = "john-workstation.internal.corp";
        
        assertFalse(DNSResolverService.isIPAddress(substitutedHostname),
                "Substituted hostname should be recognized as needing DNS resolution");
    }

    @Test
    @Label("Property 10: Dynamic hostname patterns are supported")
    void dynamicHostnamePatternsAreSupported() {
        // Feature: guacamole-dns-resolution, Property 10: Token Substitution Compatibility
        // Validates: Requirements 7.4
        
        // Common patterns that might result from token substitution
        String[] substitutedHostnames = {
            "user123-desktop.corp.local",           // ${GUAC_USERNAME}-desktop.corp.local
            "workstation-42.internal.example.com",  // workstation-${SESSION_ID}.internal.example.com
            "rdp-server-prod.datacenter.local",     // rdp-server-${ENVIRONMENT}.datacenter.local
            "vm-abc123def.cloud.internal",          // vm-${INSTANCE_ID}.cloud.internal
            "dev-john-smith.team.corp"              // dev-${GUAC_USERNAME}.team.corp
        };
        
        for (String hostname : substitutedHostnames) {
            assertFalse(DNSResolverService.isIPAddress(hostname),
                    "Substituted hostname '" + hostname + "' should require DNS resolution");
        }
    }

    @Test
    @Label("Property 10: Hostname with numbers from substitution is valid")
    void hostnameWithNumbersFromSubstitutionIsValid() {
        // Feature: guacamole-dns-resolution, Property 10: Token Substitution Compatibility
        // Validates: Requirements 7.4
        
        // Hostnames that might contain numbers from token substitution
        String[] hostnames = {
            "server001.internal.corp",
            "vm-12345.cloud.local",
            "user42-workstation.domain.com",
            "session-987654321.temp.internal"
        };
        
        for (String hostname : hostnames) {
            assertFalse(DNSResolverService.isIPAddress(hostname),
                    "Hostname with numbers '" + hostname + "' should not be mistaken for IP");
        }
    }

    @Test
    @Label("Property 10: Configuration with substituted hostname works")
    void configurationWithSubstitutedHostnameWorks() {
        // Feature: guacamole-dns-resolution, Property 10: Token Substitution Compatibility
        // Validates: Requirements 7.4
        
        GuacamoleConfiguration config = new GuacamoleConfiguration();
        config.setProtocol("rdp");
        
        // Simulate what happens after token substitution
        // Original: hostname=${GUAC_USERNAME}-workstation.${DOMAIN}
        // After substitution: hostname=jsmith-workstation.corp.local
        String substitutedHostname = "jsmith-workstation.corp.local";
        config.setParameter("hostname", substitutedHostname);
        
        // Verify the configuration is set correctly
        assertEquals(substitutedHostname, config.getParameter("hostname"));
        assertFalse(DNSResolverService.isIPAddress(substitutedHostname),
                "Substituted hostname should require DNS resolution");
    }

    @Property(tries = 100)
    @Label("Property 10: Generated substituted hostnames are valid")
    void generatedSubstitutedHostnamesAreValid(
            @ForAll("substitutedHostnames") String hostname) {
        // Feature: guacamole-dns-resolution, Property 10: Token Substitution Compatibility
        // Validates: Requirements 7.4
        
        // All generated hostnames should be recognized as hostnames (not IPs)
        assertFalse(DNSResolverService.isIPAddress(hostname),
                "Generated hostname '" + hostname + "' should not be an IP address");
        
        // Should be able to set in configuration
        GuacamoleConfiguration config = new GuacamoleConfiguration();
        config.setProtocol("rdp");
        config.setParameter("hostname", hostname);
        
        assertEquals(hostname, config.getParameter("hostname"),
                "Hostname should be stored correctly in configuration");
    }

    @Property(tries = 100)
    @Label("Property 10: Username-based hostnames work")
    void usernameBasedHostnamesWork(
            @ForAll @AlphaChars @StringLength(min = 3, max = 15) String username,
            @ForAll("domains") String domain) {
        // Feature: guacamole-dns-resolution, Property 10: Token Substitution Compatibility
        // Validates: Requirements 7.4
        
        // Simulate ${GUAC_USERNAME}-workstation.${DOMAIN}
        String hostname = username.toLowerCase() + "-workstation." + domain;
        
        assertFalse(DNSResolverService.isIPAddress(hostname),
                "Username-based hostname '" + hostname + "' should require DNS resolution");
    }

    @Property(tries = 100)
    @Label("Property 10: Session-based hostnames work")
    void sessionBasedHostnamesWork(
            @ForAll @IntRange(min = 1, max = 999999) int sessionId,
            @ForAll("domains") String domain) {
        // Feature: guacamole-dns-resolution, Property 10: Token Substitution Compatibility
        // Validates: Requirements 7.4
        
        // Simulate session-${SESSION_ID}.${DOMAIN}
        String hostname = "session-" + sessionId + "." + domain;
        
        assertFalse(DNSResolverService.isIPAddress(hostname),
                "Session-based hostname '" + hostname + "' should require DNS resolution");
    }

    @Provide
    Arbitrary<String> substitutedHostnames() {
        // Generate hostnames that look like they came from token substitution
        Arbitrary<String> userWorkstations = Combinators.combine(
                Arbitraries.strings().alpha().ofMinLength(3).ofMaxLength(10).map(String::toLowerCase),
                Arbitraries.of("workstation", "desktop", "laptop", "vm"),
                Arbitraries.of("corp.local", "internal.com", "domain.local")
        ).as((user, type, domain) -> user + "-" + type + "." + domain);
        
        Arbitrary<String> numberedServers = Combinators.combine(
                Arbitraries.of("server", "host", "node", "vm"),
                Arbitraries.integers().between(1, 999),
                Arbitraries.of("internal.corp", "cloud.local", "datacenter.net")
        ).as((prefix, num, domain) -> prefix + String.format("%03d", num) + "." + domain);
        
        Arbitrary<String> envBasedServers = Combinators.combine(
                Arbitraries.of("rdp", "ssh", "vnc"),
                Arbitraries.of("prod", "dev", "staging", "test"),
                Arbitraries.of("east", "west", "central"),
                Arbitraries.of("company.local", "internal.net")
        ).as((proto, env, region, domain) -> proto + "-" + env + "-" + region + "." + domain);
        
        return Arbitraries.oneOf(userWorkstations, numberedServers, envBasedServers);
    }

    @Provide
    Arbitrary<String> domains() {
        return Arbitraries.of(
                "corp.local",
                "internal.com",
                "company.net",
                "domain.local",
                "datacenter.internal",
                "cloud.private"
        );
    }

    @Test
    @Label("Property 10: Vault-retrieved hostnames work")
    void vaultRetrievedHostnamesWork() {
        // Feature: guacamole-dns-resolution, Property 10: Token Substitution Compatibility
        // Validates: Requirements 7.4
        
        // Simulate hostnames that might be retrieved from a vault like Keeper
        String[] vaultHostnames = {
            "secure-server-01.vault.internal",
            "production-db.secrets.corp",
            "api-gateway.confidential.local",
            "admin-console.restricted.net"
        };
        
        for (String hostname : vaultHostnames) {
            assertFalse(DNSResolverService.isIPAddress(hostname),
                    "Vault-retrieved hostname '" + hostname + "' should require DNS resolution");
            
            GuacamoleConfiguration config = new GuacamoleConfiguration();
            config.setProtocol("rdp");
            config.setParameter("hostname", hostname);
            
            assertEquals(hostname, config.getParameter("hostname"),
                    "Vault hostname should be stored correctly");
        }
    }

}
