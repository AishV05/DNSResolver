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
                Map.of(
                        "DNS_PORT", "5300",
                        "DNS_WORKER_THREADS", "4",
                        "DNS_MAX_REQUEST_BYTES", "900",
                        "DNS_REQUESTS_PER_SECOND", "25",
                        "DNS_UPSTREAM_TIMEOUT_MILLIS", "1200"
                )
        );

        assertEquals(5300, config.port());
        assertEquals(4, config.workerThreads());
        assertEquals(900, config.maxRequestBytes());
        assertEquals(25, config.requestsPerSecond());
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
                        0, 1, 1, 1, 1, 1, 1, 1, 1, 53
                )
        );
    }
}
