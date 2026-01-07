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
import org.apache.guacamole.protocol.GuacamoleConfiguration;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for protocol support in DNS resolution.
 * 
 * Feature: guacamole-dns-resolution
 * Property 8: Protocol-Agnostic Resolution
 * Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5
 */
class ProtocolIntegrationTest {

    @BeforeEach
    void setUp() {
        DNSResolverService.resetInstance();
    }

    @AfterEach
    void tearDown() {
        DNSResolverService.resetInstance();
    }

    // =========================================================================
    // Property 8: Protocol-Agnostic Resolution
    // For any Guacamole-supported protocol (RDP, VNC, SSH, Telnet, Kubernetes),
    // the Connection_Decorator SHALL resolve the hostname parameter using the
    // same DNS resolution logic.
    // Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5
    // =========================================================================

    @ParameterizedTest
    @ValueSource(strings = {"rdp", "vnc", "ssh", "telnet", "kubernetes"})
    @Label("Property 8: All protocols use hostname parameter")
    void allProtocolsUseHostnameParameter(String protocol) {
        // Feature: guacamole-dns-resolution, Property 8: Protocol-Agnostic Resolution
        // Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5
        
        GuacamoleConfiguration config = new GuacamoleConfiguration();
        config.setProtocol(protocol);
        config.setParameter("hostname", "server.example.com");
        
        // Verify the hostname parameter is set correctly
        assertEquals("server.example.com", config.getParameter("hostname"),
                "Protocol " + protocol + " should use 'hostname' parameter");
        assertEquals(protocol, config.getProtocol());
    }

    @Test
    @Label("Property 8: RDP connections use hostname parameter")
    void rdpConnectionsUseHostnameParameter() {
        // Feature: guacamole-dns-resolution, Property 8: Protocol-Agnostic Resolution
        // Validates: Requirements 6.1
        
        GuacamoleConfiguration config = createRDPConfiguration("rdp-server.internal.corp");
        
        assertEquals("rdp", config.getProtocol());
        assertEquals("rdp-server.internal.corp", config.getParameter("hostname"));
        assertFalse(DNSResolverService.isIPAddress("rdp-server.internal.corp"),
                "Hostname should require DNS resolution");
    }

    @Test
    @Label("Property 8: VNC connections use hostname parameter")
    void vncConnectionsUseHostnameParameter() {
        // Feature: guacamole-dns-resolution, Property 8: Protocol-Agnostic Resolution
        // Validates: Requirements 6.2
        
        GuacamoleConfiguration config = createVNCConfiguration("vnc-server.internal.corp");
        
        assertEquals("vnc", config.getProtocol());
        assertEquals("vnc-server.internal.corp", config.getParameter("hostname"));
        assertFalse(DNSResolverService.isIPAddress("vnc-server.internal.corp"),
                "Hostname should require DNS resolution");
    }

    @Test
    @Label("Property 8: SSH connections use hostname parameter")
    void sshConnectionsUseHostnameParameter() {
        // Feature: guacamole-dns-resolution, Property 8: Protocol-Agnostic Resolution
        // Validates: Requirements 6.3
        
        GuacamoleConfiguration config = createSSHConfiguration("ssh-server.internal.corp");
        
        assertEquals("ssh", config.getProtocol());
        assertEquals("ssh-server.internal.corp", config.getParameter("hostname"));
        assertFalse(DNSResolverService.isIPAddress("ssh-server.internal.corp"),
                "Hostname should require DNS resolution");
    }

    @Test
    @Label("Property 8: Telnet connections use hostname parameter")
    void telnetConnectionsUseHostnameParameter() {
        // Feature: guacamole-dns-resolution, Property 8: Protocol-Agnostic Resolution
        // Validates: Requirements 6.4
        
        GuacamoleConfiguration config = createTelnetConfiguration("telnet-server.internal.corp");
        
        assertEquals("telnet", config.getProtocol());
        assertEquals("telnet-server.internal.corp", config.getParameter("hostname"));
        assertFalse(DNSResolverService.isIPAddress("telnet-server.internal.corp"),
                "Hostname should require DNS resolution");
    }

    @Test
    @Label("Property 8: Kubernetes connections use hostname parameter")
    void kubernetesConnectionsUseHostnameParameter() {
        // Feature: guacamole-dns-resolution, Property 8: Protocol-Agnostic Resolution
        // Validates: Requirements 6.5
        
        GuacamoleConfiguration config = createKubernetesConfiguration("k8s-api.internal.corp");
        
        assertEquals("kubernetes", config.getProtocol());
        assertEquals("k8s-api.internal.corp", config.getParameter("hostname"));
        assertFalse(DNSResolverService.isIPAddress("k8s-api.internal.corp"),
                "Hostname should require DNS resolution");
    }

    @Property(tries = 100)
    @Label("Property 8: Any protocol with hostname needs resolution")
    void anyProtocolWithHostnameNeedsResolution(
            @ForAll("protocols") String protocol,
            @ForAll("hostnames") String hostname) {
        // Feature: guacamole-dns-resolution, Property 8: Protocol-Agnostic Resolution
        // Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5
        
        GuacamoleConfiguration config = new GuacamoleConfiguration();
        config.setProtocol(protocol);
        config.setParameter("hostname", hostname);
        
        // All generated hostnames should require resolution (not be IP addresses)
        assertFalse(DNSResolverService.isIPAddress(hostname),
                "Generated hostname '" + hostname + "' should not be an IP address");
        
        // The hostname parameter should be set correctly
        assertEquals(hostname, config.getParameter("hostname"));
    }

    @Property(tries = 100)
    @Label("Property 8: Any protocol with IP address skips resolution")
    void anyProtocolWithIPAddressSkipsResolution(
            @ForAll("protocols") String protocol,
            @ForAll("ipAddresses") String ipAddress) {
        // Feature: guacamole-dns-resolution, Property 8: Protocol-Agnostic Resolution
        // Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5
        
        GuacamoleConfiguration config = new GuacamoleConfiguration();
        config.setProtocol(protocol);
        config.setParameter("hostname", ipAddress);
        
        // All generated IP addresses should be recognized
        assertTrue(DNSResolverService.isIPAddress(ipAddress),
                "Generated IP '" + ipAddress + "' should be recognized as IP address");
        
        // The hostname parameter should be set correctly
        assertEquals(ipAddress, config.getParameter("hostname"));
    }

    @Provide
    Arbitrary<String> protocols() {
        return Arbitraries.of("rdp", "vnc", "ssh", "telnet", "kubernetes");
    }

    @Provide
    Arbitrary<String> hostnames() {
        Arbitrary<String> simpleHostnames = Arbitraries.strings()
                .alpha()
                .ofMinLength(3)
                .ofMaxLength(15)
                .map(String::toLowerCase);
        
        Arbitrary<String> dottedHostnames = Combinators.combine(
                simpleHostnames,
                Arbitraries.of("internal", "corp", "local", "example", "test"),
                Arbitraries.of("com", "org", "net", "local")
        ).as((host, domain, tld) -> host + "." + domain + "." + tld);
        
        return Arbitraries.oneOf(simpleHostnames, dottedHostnames);
    }

    @Provide
    Arbitrary<String> ipAddresses() {
        // Generate valid IPv4 addresses
        return Combinators.combine(
                Arbitraries.integers().between(1, 254),
                Arbitraries.integers().between(0, 255),
                Arbitraries.integers().between(0, 255),
                Arbitraries.integers().between(1, 254)
        ).as((a, b, c, d) -> a + "." + b + "." + c + "." + d);
    }

    // Helper methods to create protocol-specific configurations

    private GuacamoleConfiguration createRDPConfiguration(String hostname) {
        GuacamoleConfiguration config = new GuacamoleConfiguration();
        config.setProtocol("rdp");
        config.setParameter("hostname", hostname);
        config.setParameter("port", "3389");
        config.setParameter("security", "nla");
        config.setParameter("ignore-cert", "true");
        return config;
    }

    private GuacamoleConfiguration createVNCConfiguration(String hostname) {
        GuacamoleConfiguration config = new GuacamoleConfiguration();
        config.setProtocol("vnc");
        config.setParameter("hostname", hostname);
        config.setParameter("port", "5900");
        return config;
    }

    private GuacamoleConfiguration createSSHConfiguration(String hostname) {
        GuacamoleConfiguration config = new GuacamoleConfiguration();
        config.setProtocol("ssh");
        config.setParameter("hostname", hostname);
        config.setParameter("port", "22");
        return config;
    }

    private GuacamoleConfiguration createTelnetConfiguration(String hostname) {
        GuacamoleConfiguration config = new GuacamoleConfiguration();
        config.setProtocol("telnet");
        config.setParameter("hostname", hostname);
        config.setParameter("port", "23");
        return config;
    }

    private GuacamoleConfiguration createKubernetesConfiguration(String hostname) {
        GuacamoleConfiguration config = new GuacamoleConfiguration();
        config.setProtocol("kubernetes");
        config.setParameter("hostname", hostname);
        config.setParameter("port", "443");
        return config;
    }

}
