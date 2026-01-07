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

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.regex.Pattern;

import org.apache.guacamole.GuacamoleException;
import org.apache.guacamole.GuacamoleServerException;
import org.apache.guacamole.auth.dns.conf.DNSConfigurationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.Type;

/**
 * Service that handles DNS resolution using a configurable DNS server.
 * Configuration is read from guacamole.properties:
 * <ul>
 *   <li>dns-resolution-server: IP address of the DNS server to use</li>
 *   <li>dns-resolution-timeout: Timeout in milliseconds (default: 5000)</li>
 *   <li>dns-resolution-cache-ttl: Cache TTL in seconds (default: 300)</li>
 * </ul>
 * 
 * <p>This service includes a thread-safe DNS cache to reduce query load.</p>
 */
public class DNSResolverService {

    /**
     * Logger for this class.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(DNSResolverService.class);

    /**
     * Pattern for matching IPv4 addresses.
     */
    private static final Pattern IPV4_PATTERN = Pattern.compile(
            "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");

    /**
     * Pattern for matching IPv6 addresses (simplified - covers most common formats).
     */
    private static final Pattern IPV6_PATTERN = Pattern.compile(
            "^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$|" +
            "^([0-9a-fA-F]{0,4}:){2,6}((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|" +
            "^::([0-9a-fA-F]{0,4}:){0,5}[0-9a-fA-F]{0,4}$|" +
            "^[0-9a-fA-F]{0,4}::([0-9a-fA-F]{0,4}:){0,4}[0-9a-fA-F]{0,4}$");

    /**
     * Configuration service for reading settings.
     */
    private final DNSConfigurationService configService;

    /**
     * The configured DNS server address, or null if using system DNS.
     * Can be an IP address or hostname (e.g., Kubernetes service name).
     */
    private String dnsServer;

    /**
     * The configured DNS server port.
     */
    private int dnsPort;

    /**
     * The configured timeout in milliseconds.
     */
    private int timeoutMs;

    /**
     * The configured cache TTL in milliseconds.
     */
    private long cacheTTLMs;

    /**
     * Whether gateway hostnames should be resolved.
     */
    private boolean resolveGateway;

    /**
     * Whether the service has been initialized.
     */
    private volatile boolean initialized = false;

    /**
     * Lock object for thread-safe initialization.
     */
    private final Object initLock = new Object();

    /**
     * Cache of resolved DNS entries.
     */
    private final ConcurrentMap<String, CacheEntry> dnsCache = new ConcurrentHashMap<>();

    /**
     * Singleton instance of the service.
     */
    private static DNSResolverService instance;

    /**
     * Lock for singleton creation.
     */
    private static final Object INSTANCE_LOCK = new Object();

    /**
     * A cached DNS resolution result with expiration time.
     */
    private static class CacheEntry {

        /**
         * The resolved IP address.
         */
        final String ipAddress;

        /**
         * The timestamp when this entry expires (in milliseconds since epoch).
         */
        final long expiresAt;

        /**
         * Creates a new cache entry.
         *
         * @param ipAddress
         *     The resolved IP address.
         *
         * @param ttlMs
         *     The time-to-live in milliseconds.
         */
        CacheEntry(String ipAddress, long ttlMs) {
            this.ipAddress = ipAddress;
            this.expiresAt = System.currentTimeMillis() + ttlMs;
        }

        /**
         * Returns whether this cache entry has expired.
         *
         * @return
         *     true if expired, false otherwise.
         */
        boolean isExpired() {
            return System.currentTimeMillis() > expiresAt;
        }
    }

    /**
     * Creates a new DNSResolverService with the default configuration service.
     */
    public DNSResolverService() {
        this.configService = new DNSConfigurationService();
    }

    /**
     * Creates a new DNSResolverService with the provided configuration service.
     * This constructor is primarily for testing.
     *
     * @param configService
     *     The configuration service to use.
     */
    public DNSResolverService(DNSConfigurationService configService) {
        this.configService = configService;
    }

    /**
     * Returns the singleton instance of the DNSResolverService, creating it
     * if necessary.
     *
     * @return
     *     The singleton DNSResolverService instance.
     */
    public static DNSResolverService getInstance() {
        if (instance == null) {
            synchronized (INSTANCE_LOCK) {
                if (instance == null) {
                    instance = new DNSResolverService();
                }
            }
        }
        return instance;
    }

    /**
     * Initializes the DNS resolver service by reading configuration from
     * guacamole.properties. This method is thread-safe and will only
     * initialize once.
     *
     * @throws GuacamoleException
     *     If an error occurs reading configuration.
     */
    public void initialize() throws GuacamoleException {
        if (initialized) {
            return;
        }

        synchronized (initLock) {
            if (initialized) {
                return;
            }

            // Read DNS server from configuration (can be IP or hostname)
            String serverConfig = configService.getDNSServer();
            if (serverConfig != null) {
                dnsServer = serverConfig;
                LOGGER.info("DNS resolution extension configured to use DNS server: {}", dnsServer);
            } else {
                LOGGER.info("No custom DNS server configured. Using system DNS.");
                dnsServer = null;
            }

            // Read DNS port from configuration
            dnsPort = configService.getPort();
            LOGGER.info("DNS resolution port configured to {}", dnsPort);

            // Read timeout from configuration
            timeoutMs = configService.getTimeout();
            LOGGER.info("DNS resolution timeout configured to {}ms", timeoutMs);

            // Read cache TTL from configuration
            int cacheTTLSeconds = configService.getCacheTTL();
            cacheTTLMs = cacheTTLSeconds * 1000L;
            if (cacheTTLMs > 0) {
                LOGGER.info("DNS resolution cache TTL configured to {} seconds", cacheTTLSeconds);
            } else {
                LOGGER.info("DNS resolution caching disabled (TTL = 0)");
            }

            // Read gateway resolution setting
            resolveGateway = configService.getResolveGateway();
            LOGGER.info("Gateway hostname resolution: {}", resolveGateway ? "enabled" : "disabled");

            initialized = true;
        }
    }

    /**
     * Returns whether gateway hostnames should be resolved.
     *
     * @return
     *     true if gateway hostnames should be resolved, false otherwise.
     *
     * @throws GuacamoleException
     *     If an error occurs during initialization.
     */
    public boolean shouldResolveGateway() throws GuacamoleException {
        initialize();
        return resolveGateway;
    }

    /**
     * Checks if the given string is a valid IPv4 or IPv6 address.
     *
     * @param address
     *     The string to check.
     *
     * @return
     *     true if the string is a valid IP address, false otherwise.
     */
    public static boolean isValidIPAddress(String address) {
        if (address == null || address.isEmpty()) {
            return false;
        }
        return isIPv4Address(address) || isIPv6Address(address);
    }

    /**
     * Checks if the given string is a valid IPv4 address.
     *
     * @param address
     *     The string to check.
     *
     * @return
     *     true if the string is a valid IPv4 address, false otherwise.
     */
    public static boolean isIPv4Address(String address) {
        if (address == null || address.isEmpty()) {
            return false;
        }
        return IPV4_PATTERN.matcher(address).matches();
    }

    /**
     * Checks if the given string is a valid IPv6 address.
     *
     * @param address
     *     The string to check.
     *
     * @return
     *     true if the string is a valid IPv6 address, false otherwise.
     */
    public static boolean isIPv6Address(String address) {
        if (address == null || address.isEmpty()) {
            return false;
        }
        // Handle IPv6 addresses enclosed in brackets
        String cleanAddress = address;
        if (address.startsWith("[") && address.endsWith("]")) {
            cleanAddress = address.substring(1, address.length() - 1);
        }
        return IPV6_PATTERN.matcher(cleanAddress).matches();
    }

    /**
     * Checks if the given string is an IP address (IPv4 or IPv6).
     *
     * @param address
     *     The string to check.
     *
     * @return
     *     true if the string is an IP address, false otherwise.
     */
    public static boolean isIPAddress(String address) {
        return isValidIPAddress(address);
    }

    /**
     * Resolves a hostname to an IP address using the configured DNS server,
     * or system DNS if no custom server is configured. Results are cached
     * according to the configured TTL.
     *
     * @param hostname
     *     The hostname to resolve.
     *
     * @return
     *     The resolved IP address as a string.
     *
     * @throws GuacamoleException
     *     If DNS resolution fails.
     */
    public String resolve(String hostname) throws GuacamoleException {
        initialize();

        if (hostname == null || hostname.trim().isEmpty()) {
            throw new GuacamoleServerException("Hostname cannot be null or empty");
        }

        hostname = hostname.trim();

        // If it's already an IP address, return it as-is
        if (isIPAddress(hostname)) {
            LOGGER.debug("Hostname '{}' is already an IP address, skipping DNS resolution", hostname);
            return hostname;
        }

        // Check cache first (if caching is enabled)
        if (cacheTTLMs > 0) {
            CacheEntry cached = dnsCache.get(hostname.toLowerCase());
            if (cached != null && !cached.isExpired()) {
                LOGGER.debug("Cache hit for hostname '{}': {}", hostname, cached.ipAddress);
                return cached.ipAddress;
            }
        }

        // Perform DNS resolution
        String resolvedIP;
        if (dnsServer != null) {
            resolvedIP = resolveWithCustomDNS(hostname);
        } else {
            resolvedIP = resolveWithSystemDNS(hostname);
        }

        // Cache the result (if caching is enabled)
        if (cacheTTLMs > 0) {
            dnsCache.put(hostname.toLowerCase(), new CacheEntry(resolvedIP, cacheTTLMs));
            LOGGER.debug("Cached DNS resolution for '{}': {} (TTL: {}ms)", 
                    hostname, resolvedIP, cacheTTLMs);
        }

        return resolvedIP;
    }

    /**
     * Resolves a hostname using the configured custom DNS server.
     *
     * @param hostname
     *     The hostname to resolve.
     *
     * @return
     *     The resolved IP address as a string.
     *
     * @throws GuacamoleException
     *     If DNS resolution fails.
     */
    private String resolveWithCustomDNS(String hostname) throws GuacamoleException {
        LOGGER.debug("Resolving hostname '{}' using custom DNS server '{}:{}'", 
                hostname, dnsServer, dnsPort);

        try {
            // Create resolver with custom DNS server and port
            SimpleResolver resolver = new SimpleResolver(dnsServer);
            resolver.setPort(dnsPort);
            resolver.setTimeout(Duration.ofMillis(timeoutMs));

            // Try A record (IPv4) first
            Lookup lookup = new Lookup(hostname, Type.A);
            lookup.setResolver(resolver);
            Record[] records = lookup.run();

            if (records != null && records.length > 0) {
                for (Record record : records) {
                    if (record instanceof ARecord) {
                        String resolvedIP = ((ARecord) record).getAddress().getHostAddress();
                        LOGGER.debug("Resolved hostname '{}' to IP '{}' using DNS server '{}:{}'",
                                hostname, resolvedIP, dnsServer, dnsPort);
                        return resolvedIP;
                    }
                }
            }

            // Try AAAA record (IPv6) if no A record found
            lookup = new Lookup(hostname, Type.AAAA);
            lookup.setResolver(resolver);
            records = lookup.run();

            if (records != null && records.length > 0) {
                for (Record record : records) {
                    if (record instanceof AAAARecord) {
                        String resolvedIP = ((AAAARecord) record).getAddress().getHostAddress();
                        LOGGER.debug("Resolved hostname '{}' to IPv6 '{}' using DNS server '{}:{}'",
                                hostname, resolvedIP, dnsServer, dnsPort);
                        return resolvedIP;
                    }
                }
            }

            // No records found
            LOGGER.warn("DNS resolution failed for hostname '{}' using DNS server '{}:{}': Host not found",
                    hostname, dnsServer, dnsPort);
            throw new GuacamoleServerException(
                    "Unable to resolve hostname '" + hostname + "': Host not found");

        } catch (UnknownHostException e) {
            LOGGER.warn("DNS resolution failed for hostname '{}': DNS server '{}:{}' is unreachable",
                    hostname, dnsServer, dnsPort);
            throw new GuacamoleServerException(
                    "Unable to resolve hostname '" + hostname + "': DNS server unreachable", e);
        } catch (GuacamoleException e) {
            throw e;
        } catch (Exception e) {
            LOGGER.warn("DNS resolution failed for hostname '{}' using DNS server '{}:{}': {}",
                    hostname, dnsServer, dnsPort, e.getMessage());
            throw new GuacamoleServerException(
                    "Unable to resolve hostname '" + hostname + "': " + e.getMessage(), e);
        }
    }

    /**
     * Resolves a hostname using the system's default DNS resolver.
     *
     * @param hostname
     *     The hostname to resolve.
     *
     * @return
     *     The resolved IP address as a string.
     *
     * @throws GuacamoleException
     *     If DNS resolution fails.
     */
    private String resolveWithSystemDNS(String hostname) throws GuacamoleException {
        LOGGER.debug("Resolving hostname '{}' using system DNS", hostname);

        try {
            InetAddress address = InetAddress.getByName(hostname);
            String resolvedIP = address.getHostAddress();
            LOGGER.debug("Resolved hostname '{}' to IP '{}' using system DNS", hostname, resolvedIP);
            return resolvedIP;
        } catch (UnknownHostException e) {
            LOGGER.warn("DNS resolution failed for hostname '{}' using system DNS: {}",
                    hostname, e.getMessage());
            throw new GuacamoleServerException(
                    "Unable to resolve hostname '" + hostname + "': " + e.getMessage(), e);
        }
    }

    /**
     * Returns the currently configured DNS server, or null if using system DNS.
     * Primarily for testing purposes.
     *
     * @return
     *     The configured DNS server address, or null.
     *
     * @throws GuacamoleException
     *     If an error occurs during initialization.
     */
    public String getConfiguredDNSServer() throws GuacamoleException {
        initialize();
        return dnsServer;
    }

    /**
     * Returns the currently configured timeout in milliseconds.
     * Primarily for testing purposes.
     *
     * @return
     *     The configured timeout in milliseconds.
     *
     * @throws GuacamoleException
     *     If an error occurs during initialization.
     */
    public int getConfiguredTimeout() throws GuacamoleException {
        initialize();
        return timeoutMs;
    }

    /**
     * Returns the current cache size.
     * Primarily for testing purposes.
     *
     * @return
     *     The number of entries in the DNS cache.
     */
    public int getCacheSize() {
        return dnsCache.size();
    }

    /**
     * Clears the DNS cache.
     * Primarily for testing purposes.
     */
    public void clearCache() {
        dnsCache.clear();
    }

    /**
     * Resets the singleton instance. This is primarily for testing purposes.
     */
    static void resetInstance() {
        synchronized (INSTANCE_LOCK) {
            instance = null;
        }
    }

    /**
     * Resets the service to uninitialized state. This is primarily for testing
     * purposes to allow re-initialization with different configuration.
     */
    void reset() {
        synchronized (initLock) {
            initialized = false;
            dnsServer = null;
            dnsPort = DNSConfigurationService.DEFAULT_PORT;
            timeoutMs = DNSConfigurationService.DEFAULT_TIMEOUT_MS;
            cacheTTLMs = DNSConfigurationService.DEFAULT_CACHE_TTL_SECONDS * 1000L;
            resolveGateway = DNSConfigurationService.DEFAULT_RESOLVE_GATEWAY;
            dnsCache.clear();
        }
    }

}
