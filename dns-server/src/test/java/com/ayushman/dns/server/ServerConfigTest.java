package com.ayushman.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Map;
import java.util.Properties;

import org.junit.jupiter.api.Test;

public class ServerConfigTest {

    @Test
    void shouldLoadSettingsFromEnvironment() {

        ServerConfig config = ServerConfig.from(
                new Properties(),
                Map.ofEntries(
                        Map.entry("DNS_PORT", "5300"),
                        Map.entry("DNS_WORKER_THREADS", "4"),
                        Map.entry("DNS_MAX_REQUEST_BYTES", "900"),
                        Map.entry("DNS_REQUESTS_PER_SECOND", "25"),
                        Map.entry("DNS_TCP_MAX_CONNECTIONS", "80"),
                        Map.entry(
                                "DNS_TCP_MAX_CONNECTIONS_PER_CLIENT",
                                "8"
                        ),
                        Map.entry("DNS_TCP_IDLE_TIMEOUT_MILLIS", "7000"),
                        Map.entry(
                                "DNS_TCP_MESSAGE_TIMEOUT_MILLIS",
                                "3000"
                        ),
                        Map.entry("DNS_HEALTH_PORT", "8181"),
                        Map.entry("DNS_METRICS_PORT", "9191"),
                        Map.entry(
                                "DNS_METRICS_BIND_ADDRESS",
                                "0.0.0.0"
                        ),
                        Map.entry(
                                "DNS_UPSTREAM_TIMEOUT_MILLIS",
                                "1200"
                        )
                )
        );

        assertEquals(5300, config.port());
        assertEquals(4, config.workerThreads());
        assertEquals(900, config.maxRequestBytes());
        assertEquals(25, config.requestsPerSecond());
        assertEquals(80, config.tcpMaxConnections());
        assertEquals(8, config.tcpMaxConnectionsPerClient());
        assertEquals(7000, config.tcpIdleTimeoutMillis());
        assertEquals(3000, config.tcpMessageTimeoutMillis());
        assertEquals(8181, config.healthPort());
        assertEquals(9191, config.metricsPort());
        assertEquals("0.0.0.0", config.metricsBindAddress());
        assertEquals(1200, config.upstreamTimeoutMillis());
        assertEquals(200, config.workerQueueCapacity());
    }

    @Test
    void shouldPreferSystemPropertiesOverEnvironment() {

        Properties properties = new Properties();
        properties.setProperty("dns.port", "5400");
        properties.setProperty("dns.upstreamPort", "5301");

        ServerConfig config = ServerConfig.from(
                properties,
                Map.of(
                        "DNS_PORT", "5300",
                        "DNS_UPSTREAM_PORT", "53"
                )
        );

        assertEquals(5400, config.port());
        assertEquals(5301, config.upstreamPort());
    }

    @Test
    void shouldRejectInvalidSettings() {

        Properties properties = new Properties();
        properties.setProperty("dns.port", "not-a-port");

        assertThrows(
                IllegalArgumentException.class,
                () -> ServerConfig.from(properties, Map.of())
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> new ServerConfig(
                        0, 1, 1, 1, 1, 1,
                        2, 1, 1, 1, 1, 1, 1,
                        1, 8080, 9091, "127.0.0.1", 1, 1, 53
                )
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> new ServerConfig(
                        5354, 1, 1, 1, 1, 1,
                        2, 1, 1, 1, 1, 1, 1,
                        1, 8080, 8080, "127.0.0.1", 1, 1, 53
                )
        );

        Properties invalidConnections = new Properties();
        invalidConnections.setProperty("dns.tcp.maxConnections", "2");
        invalidConnections.setProperty(
                "dns.tcp.maxConnectionsPerClient",
                "3"
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> ServerConfig.from(invalidConnections, Map.of())
        );

        Properties excessiveConnections = new Properties();
        excessiveConnections.setProperty(
                "dns.tcp.maxConnections",
                "100001"
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> ServerConfig.from(excessiveConnections, Map.of())
        );

        Properties excessiveTimeout = new Properties();
        excessiveTimeout.setProperty(
                "dns.tcp.idleTimeoutMillis",
                "600001"
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> ServerConfig.from(excessiveTimeout, Map.of())
        );
    }
}
