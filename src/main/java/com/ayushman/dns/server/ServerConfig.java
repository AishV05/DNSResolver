package com.ayushman.dns.server;

import java.util.Map;
import java.util.Properties;

/**
 * Runtime settings for the UDP server and its upstream DNS client.
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
        int metricsIntervalSeconds,
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
    private static final int DEFAULT_METRICS_INTERVAL_SECONDS = 60;
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
        validatePositive(metricsIntervalSeconds, "metricsIntervalSeconds");
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
                DEFAULT_METRICS_INTERVAL_SECONDS,
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
                        "dns.metricsIntervalSeconds",
                        "DNS_METRICS_INTERVAL_SECONDS",
                        DEFAULT_METRICS_INTERVAL_SECONDS),
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
                metricsIntervalSeconds,
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
}
