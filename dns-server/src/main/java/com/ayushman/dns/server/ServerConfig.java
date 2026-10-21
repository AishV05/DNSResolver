package com.ayushman.dns.server;

import java.util.Map;
import java.util.Properties;

/**
 * Runtime settings for the dual-transport server and its upstream DNS client.
 *
 * System properties take precedence over environment variables. For example,
 * {@code -Ddns.port=5355} overrides {@code DNS_PORT=5354}.
 */
public record ServerConfig(
        int port,
        int workerThreads,
        int workerQueueCapacity,
        int maxRequestBytes,
        int requestsPerSecond,
        int requestBurstCapacity,
        int tcpMaxConnections,
        int tcpMaxConnectionsPerClient,
        int tcpAcceptBacklog,
        int tcpIdleTimeoutMillis,
        int tcpMessageTimeoutMillis,
        int tcpMaxQueriesPerConnection,
        int tcpMaxRequestBytes,
        int metricsIntervalSeconds,
        int healthPort,
        int metricsPort,
        String metricsBindAddress,
        int upstreamTimeoutMillis,
        int upstreamMaxAttempts,
        int upstreamPort
) {

    private static final int DEFAULT_PORT = 5_354;
    private static final int DEFAULT_WORKER_THREADS = 10;
    private static final int DEFAULT_WORKER_QUEUE_CAPACITY = 200;
    private static final int DEFAULT_MAX_REQUEST_BYTES =
            RequestAdmissionController.DEFAULT_MAX_REQUEST_BYTES;
    private static final int DEFAULT_REQUESTS_PER_SECOND = 100;
    private static final int DEFAULT_REQUEST_BURST_CAPACITY = 200;
    private static final int DEFAULT_TCP_MAX_CONNECTIONS = 200;
    private static final int DEFAULT_TCP_MAX_CONNECTIONS_PER_CLIENT = 20;
    private static final int DEFAULT_TCP_ACCEPT_BACKLOG = 128;
    private static final int DEFAULT_TCP_IDLE_TIMEOUT_MILLIS = 10_000;
    private static final int DEFAULT_TCP_MESSAGE_TIMEOUT_MILLIS = 5_000;
    private static final int DEFAULT_TCP_MAX_QUERIES_PER_CONNECTION = 100;
    private static final int DEFAULT_TCP_MAX_REQUEST_BYTES = 65_535;
    private static final int DEFAULT_METRICS_INTERVAL_SECONDS = 60;
    private static final int DEFAULT_HEALTH_PORT = 8_080;
    private static final int DEFAULT_METRICS_PORT = 9_091;
    private static final String DEFAULT_METRICS_BIND_ADDRESS = "127.0.0.1";
    private static final int DEFAULT_UPSTREAM_TIMEOUT_MILLIS = 2_000;
    private static final int DEFAULT_UPSTREAM_MAX_ATTEMPTS = 2;
    private static final int DEFAULT_UPSTREAM_PORT = 53;

    public ServerConfig {
        validatePort(port, "port");
        validatePositive(workerThreads, "workerThreads");
        validatePositive(workerQueueCapacity, "workerQueueCapacity");

        if (maxRequestBytes <= 0 || maxRequestBytes > 65_535) {
            throw new IllegalArgumentException(
                    "maxRequestBytes must be between 1 and 65535"
            );
        }

        validatePositive(requestsPerSecond, "requestsPerSecond");
        validatePositive(requestBurstCapacity, "requestBurstCapacity");
        validateRange(
                tcpMaxConnections,
                1,
                100_000,
                "tcpMaxConnections"
        );
        validateRange(
                tcpMaxConnectionsPerClient,
                1,
                100_000,
                "tcpMaxConnectionsPerClient"
        );
        if (tcpMaxConnectionsPerClient > tcpMaxConnections) {
            throw new IllegalArgumentException(
                    "tcpMaxConnectionsPerClient must not exceed "
                            + "tcpMaxConnections"
            );
        }
        validateRange(tcpAcceptBacklog, 1, 65_535, "tcpAcceptBacklog");
        validateRange(
                tcpIdleTimeoutMillis,
                1,
                600_000,
                "tcpIdleTimeoutMillis"
        );
        validateRange(
                tcpMessageTimeoutMillis,
                1,
                600_000,
                "tcpMessageTimeoutMillis"
        );
        validateRange(
                tcpMaxQueriesPerConnection,
                1,
                100_000,
                "tcpMaxQueriesPerConnection"
        );
        if (tcpMaxRequestBytes <= 0 || tcpMaxRequestBytes > 65_535) {
            throw new IllegalArgumentException(
                    "tcpMaxRequestBytes must be between 1 and 65535"
            );
        }
        validatePositive(metricsIntervalSeconds, "metricsIntervalSeconds");
        validatePort(healthPort, "healthPort");
        validatePort(metricsPort, "metricsPort");
        validateNonBlank(metricsBindAddress, "metricsBindAddress");

        if (healthPort == metricsPort) {
            throw new IllegalArgumentException(
                    "healthPort and metricsPort must differ"
            );
        }

        validatePositive(upstreamTimeoutMillis, "upstreamTimeoutMillis");
        validatePositive(upstreamMaxAttempts, "upstreamMaxAttempts");
        validatePort(upstreamPort, "upstreamPort");
    }

    public static ServerConfig fromSystem() {
        return from(
                System.getProperties(),
                System.getenv()
        );
    }

    static ServerConfig defaults() {
        return new ServerConfig(
                DEFAULT_PORT,
                DEFAULT_WORKER_THREADS,
                DEFAULT_WORKER_QUEUE_CAPACITY,
                DEFAULT_MAX_REQUEST_BYTES,
                DEFAULT_REQUESTS_PER_SECOND,
                DEFAULT_REQUEST_BURST_CAPACITY,
                DEFAULT_TCP_MAX_CONNECTIONS,
                DEFAULT_TCP_MAX_CONNECTIONS_PER_CLIENT,
                DEFAULT_TCP_ACCEPT_BACKLOG,
                DEFAULT_TCP_IDLE_TIMEOUT_MILLIS,
                DEFAULT_TCP_MESSAGE_TIMEOUT_MILLIS,
                DEFAULT_TCP_MAX_QUERIES_PER_CONNECTION,
                DEFAULT_TCP_MAX_REQUEST_BYTES,
                DEFAULT_METRICS_INTERVAL_SECONDS,
                DEFAULT_HEALTH_PORT,
                DEFAULT_METRICS_PORT,
                DEFAULT_METRICS_BIND_ADDRESS,
                DEFAULT_UPSTREAM_TIMEOUT_MILLIS,
                DEFAULT_UPSTREAM_MAX_ATTEMPTS,
                DEFAULT_UPSTREAM_PORT
        );
    }

    static ServerConfig from(
            Properties properties,
            Map<String, String> environment
    ) {

        if (properties == null || environment == null) {
            throw new IllegalArgumentException(
                    "properties and environment must not be null"
            );
        }

        return new ServerConfig(
                readInt(properties, environment,
                        "dns.port", "DNS_PORT", DEFAULT_PORT),
                readInt(properties, environment,
                        "dns.workerThreads", "DNS_WORKER_THREADS",
                        DEFAULT_WORKER_THREADS),
                readInt(properties, environment,
                        "dns.workerQueueCapacity",
                        "DNS_WORKER_QUEUE_CAPACITY",
                        DEFAULT_WORKER_QUEUE_CAPACITY),
                readInt(properties, environment,
                        "dns.maxRequestBytes", "DNS_MAX_REQUEST_BYTES",
                        DEFAULT_MAX_REQUEST_BYTES),
                readInt(properties, environment,
                        "dns.requestsPerSecond",
                        "DNS_REQUESTS_PER_SECOND",
                        DEFAULT_REQUESTS_PER_SECOND),
                readInt(properties, environment,
                        "dns.requestBurstCapacity",
                        "DNS_REQUEST_BURST_CAPACITY",
                        DEFAULT_REQUEST_BURST_CAPACITY),
                readInt(properties, environment,
                        "dns.tcp.maxConnections",
                        "DNS_TCP_MAX_CONNECTIONS",
                        DEFAULT_TCP_MAX_CONNECTIONS),
                readInt(properties, environment,
                        "dns.tcp.maxConnectionsPerClient",
                        "DNS_TCP_MAX_CONNECTIONS_PER_CLIENT",
                        DEFAULT_TCP_MAX_CONNECTIONS_PER_CLIENT),
                readInt(properties, environment,
                        "dns.tcp.acceptBacklog",
                        "DNS_TCP_ACCEPT_BACKLOG",
                        DEFAULT_TCP_ACCEPT_BACKLOG),
                readInt(properties, environment,
                        "dns.tcp.idleTimeoutMillis",
                        "DNS_TCP_IDLE_TIMEOUT_MILLIS",
                        DEFAULT_TCP_IDLE_TIMEOUT_MILLIS),
                readInt(properties, environment,
                        "dns.tcp.messageTimeoutMillis",
                        "DNS_TCP_MESSAGE_TIMEOUT_MILLIS",
                        DEFAULT_TCP_MESSAGE_TIMEOUT_MILLIS),
                readInt(properties, environment,
                        "dns.tcp.maxQueriesPerConnection",
                        "DNS_TCP_MAX_QUERIES_PER_CONNECTION",
                        DEFAULT_TCP_MAX_QUERIES_PER_CONNECTION),
                readInt(properties, environment,
                        "dns.tcp.maxRequestBytes",
                        "DNS_TCP_MAX_REQUEST_BYTES",
                        DEFAULT_TCP_MAX_REQUEST_BYTES),
                readInt(properties, environment,
                        "dns.metricsIntervalSeconds",
                        "DNS_METRICS_INTERVAL_SECONDS",
                        DEFAULT_METRICS_INTERVAL_SECONDS),
                readInt(properties, environment,
                        "dns.healthPort", "DNS_HEALTH_PORT",
                        DEFAULT_HEALTH_PORT),
                readInt(properties, environment,
                        "dns.metricsPort", "DNS_METRICS_PORT",
                        DEFAULT_METRICS_PORT),
                readString(properties, environment,
                        "dns.metricsBindAddress",
                        "DNS_METRICS_BIND_ADDRESS",
                        DEFAULT_METRICS_BIND_ADDRESS),
                readInt(properties, environment,
                        "dns.upstreamTimeoutMillis",
                        "DNS_UPSTREAM_TIMEOUT_MILLIS",
                        DEFAULT_UPSTREAM_TIMEOUT_MILLIS),
                readInt(properties, environment,
                        "dns.upstreamMaxAttempts",
                        "DNS_UPSTREAM_MAX_ATTEMPTS",
                        DEFAULT_UPSTREAM_MAX_ATTEMPTS),
                readInt(properties, environment,
                        "dns.upstreamPort", "DNS_UPSTREAM_PORT",
                        DEFAULT_UPSTREAM_PORT)
        );
    }

    ServerConfig withPort(
            int configuredPort
    ) {

        return new ServerConfig(
                configuredPort,
                workerThreads,
                workerQueueCapacity,
                maxRequestBytes,
                requestsPerSecond,
                requestBurstCapacity,
                tcpMaxConnections,
                tcpMaxConnectionsPerClient,
                tcpAcceptBacklog,
                tcpIdleTimeoutMillis,
                tcpMessageTimeoutMillis,
                tcpMaxQueriesPerConnection,
                tcpMaxRequestBytes,
                metricsIntervalSeconds,
                healthPort,
                metricsPort,
                metricsBindAddress,
                upstreamTimeoutMillis,
                upstreamMaxAttempts,
                upstreamPort
        );
    }

    private static int readInt(
            Properties properties,
            Map<String, String> environment,
            String propertyName,
            String environmentName,
            int defaultValue
    ) {

        String value = properties.getProperty(propertyName);

        if (value == null || value.isBlank()) {
            value = environment.get(environmentName);
        }

        if (value == null || value.isBlank()) {
            return defaultValue;
        }

        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                    propertyName + " must be an integer",
                    e
            );
        }
    }

    private static String readString(
            Properties properties,
            Map<String, String> environment,
            String propertyName,
            String environmentName,
            String defaultValue
    ) {

        String value = properties.getProperty(propertyName);

        if (value == null || value.isBlank()) {
            value = environment.get(environmentName);
        }

        return value == null || value.isBlank()
                ? defaultValue
                : value;
    }

    private static void validatePositive(
            int value,
            String fieldName
    ) {

        if (value <= 0) {
            throw new IllegalArgumentException(
                    fieldName + " must be positive"
            );
        }
    }

    private static void validatePort(
            int value,
            String fieldName
    ) {

        if (value < 1 || value > 65_535) {
            throw new IllegalArgumentException(
                    fieldName + " must be between 1 and 65535"
            );
        }
    }

    private static void validateRange(
            int value,
            int minimum,
            int maximum,
            String fieldName
    ) {

        if (value < minimum || value > maximum) {
            throw new IllegalArgumentException(
                    fieldName + " must be between "
                            + minimum + " and " + maximum
            );
        }
    }

    private static void validateNonBlank(
            String value,
            String fieldName
    ) {

        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException(
                    fieldName + " must not be blank"
            );
        }
    }
}
