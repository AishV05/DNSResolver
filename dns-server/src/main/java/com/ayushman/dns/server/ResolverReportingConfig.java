package com.ayushman.dns.server;

import java.net.URI;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.UUID;

import com.ayushman.dns.fleet.ResolverSessionStart;

/** Bounded configuration for the resolver fleet reporting loop. */
public record ResolverReportingConfig(
        ResolverReportingMode mode,
        URI controlPlaneUri,
        Path tokenFile,
        String applicationVersion,
        boolean allowInsecureHttp,
        int connectTimeoutMillis,
        int requestTimeoutMillis,
        int reportIntervalMillis,
        int initialBackoffMillis,
        int maxBackoffMillis,
        int maxResponseBytes
) {

    private static final UUID VALIDATION_BOOT_ID =
            UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final int DEFAULT_CONNECT_TIMEOUT_MILLIS = 2_000;
    private static final int DEFAULT_REQUEST_TIMEOUT_MILLIS = 5_000;
    private static final int DEFAULT_REPORT_INTERVAL_MILLIS = 30_000;
    private static final int DEFAULT_INITIAL_BACKOFF_MILLIS = 1_000;
    private static final int DEFAULT_MAX_BACKOFF_MILLIS = 30_000;
    private static final int DEFAULT_MAX_RESPONSE_BYTES = 16_384;

    public ResolverReportingConfig {
        if (mode == null) {
            throw new IllegalArgumentException(
                    "resolver reporting mode must not be null"
            );
        }
        if (applicationVersion == null) {
            throw new IllegalArgumentException(
                    "resolver application version must not be null"
            );
        }
        new ResolverSessionStart(VALIDATION_BOOT_ID, applicationVersion);

        validateRange(connectTimeoutMillis, 100, 60_000,
                "connectTimeoutMillis");
        validateRange(requestTimeoutMillis, 100, 120_000,
                "requestTimeoutMillis");
        if (requestTimeoutMillis < connectTimeoutMillis) {
            throw new IllegalArgumentException(
                    "requestTimeoutMillis must not be less than "
                            + "connectTimeoutMillis"
            );
        }
        validateRange(reportIntervalMillis, 100, 3_600_000,
                "reportIntervalMillis");
        validateRange(initialBackoffMillis, 100, 3_600_000,
                "initialBackoffMillis");
        validateRange(maxBackoffMillis, 100, 3_600_000,
                "maxBackoffMillis");
        if (initialBackoffMillis > maxBackoffMillis) {
            throw new IllegalArgumentException(
                    "initialBackoffMillis must not exceed maxBackoffMillis"
            );
        }
        validateRange(maxResponseBytes, 256, 1_048_576,
                "maxResponseBytes");

        if (controlPlaneUri != null) {
            validateControlPlaneUri(controlPlaneUri, allowInsecureHttp);
        }
        if (tokenFile != null && !tokenFile.isAbsolute()) {
            throw new IllegalArgumentException(
                    "resolver reporting token file must be absolute"
            );
        }
        if (mode == ResolverReportingMode.ENABLED) {
            if (controlPlaneUri == null) {
                throw new IllegalArgumentException(
                        "control-plane URI is required when reporting is enabled"
                );
            }
            if (tokenFile == null) {
                throw new IllegalArgumentException(
                        "token file is required when reporting is enabled"
                );
            }
        }
    }

    public static ResolverReportingConfig fromSystem() {
        return from(System.getProperties(), System.getenv());
    }

    static ResolverReportingConfig from(
            Properties properties,
            Map<String, String> environment
    ) {
        if (properties == null || environment == null) {
            throw new IllegalArgumentException(
                    "properties and environment must not be null"
            );
        }

        String uri = readString(
                properties,
                environment,
                "dns.reporting.controlPlaneUrl",
                "DNS_REPORTING_CONTROL_PLANE_URL"
        );
        String tokenFile = readString(
                properties,
                environment,
                "dns.reporting.tokenFile",
                "DNS_REPORTING_TOKEN_FILE"
        );
        String applicationVersion = readString(
                properties,
                environment,
                "dns.applicationVersion",
                "DNS_APPLICATION_VERSION"
        );

        return new ResolverReportingConfig(
                readMode(properties, environment),
                parseUri(uri),
                parsePath(tokenFile),
                applicationVersion == null ? "development" : applicationVersion,
                readBoolean(
                        properties,
                        environment,
                        "dns.reporting.allowInsecureHttp",
                        "DNS_REPORTING_ALLOW_INSECURE_HTTP",
                        false
                ),
                readInt(properties, environment,
                        "dns.reporting.connectTimeoutMillis",
                        "DNS_REPORTING_CONNECT_TIMEOUT_MILLIS",
                        DEFAULT_CONNECT_TIMEOUT_MILLIS),
                readInt(properties, environment,
                        "dns.reporting.requestTimeoutMillis",
                        "DNS_REPORTING_REQUEST_TIMEOUT_MILLIS",
                        DEFAULT_REQUEST_TIMEOUT_MILLIS),
                readInt(properties, environment,
                        "dns.reporting.reportIntervalMillis",
                        "DNS_REPORTING_INTERVAL_MILLIS",
                        DEFAULT_REPORT_INTERVAL_MILLIS),
                readInt(properties, environment,
                        "dns.reporting.initialBackoffMillis",
                        "DNS_REPORTING_INITIAL_BACKOFF_MILLIS",
                        DEFAULT_INITIAL_BACKOFF_MILLIS),
                readInt(properties, environment,
                        "dns.reporting.maxBackoffMillis",
                        "DNS_REPORTING_MAX_BACKOFF_MILLIS",
                        DEFAULT_MAX_BACKOFF_MILLIS),
                readInt(properties, environment,
                        "dns.reporting.maxResponseBytes",
                        "DNS_REPORTING_MAX_RESPONSE_BYTES",
                        DEFAULT_MAX_RESPONSE_BYTES)
        );
    }

    URI sessionUri() {
        return controlPlaneUri.resolve("/api/v1/internal/resolver/session");
    }

    URI reportUri() {
        return controlPlaneUri.resolve("/api/v1/internal/resolver/report");
    }

    private static ResolverReportingMode readMode(
            Properties properties,
            Map<String, String> environment
    ) {
        String value = readString(
                properties,
                environment,
                "dns.reporting.mode",
                "DNS_REPORTING_MODE"
        );
        if (value == null) {
            return ResolverReportingMode.DISABLED;
        }
        try {
            return ResolverReportingMode.valueOf(
                    value.toUpperCase(Locale.ROOT)
            );
        } catch (IllegalArgumentException invalidMode) {
            throw new IllegalArgumentException(
                    "dns.reporting.mode must be DISABLED or ENABLED",
                    invalidMode
            );
        }
    }

    private static URI parseUri(String value) {
        if (value == null) {
            return null;
        }
        try {
            return URI.create(value);
        } catch (IllegalArgumentException invalidUri) {
            throw new IllegalArgumentException(
                    "dns.reporting.controlPlaneUrl must be a valid URI",
                    invalidUri
            );
        }
    }

    private static Path parsePath(String value) {
        if (value == null) {
            return null;
        }
        try {
            return Path.of(value);
        } catch (RuntimeException invalidPath) {
            throw new IllegalArgumentException(
                    "dns.reporting.tokenFile must be a valid path",
                    invalidPath
            );
        }
    }

    private static int readInt(
            Properties properties,
            Map<String, String> environment,
            String propertyName,
            String environmentName,
            int defaultValue
    ) {
        String value = readString(
                properties,
                environment,
                propertyName,
                environmentName
        );
        if (value == null) {
            return defaultValue;
        }
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException invalidNumber) {
            throw new IllegalArgumentException(
                    propertyName + " must be an integer",
                    invalidNumber
            );
        }
    }

    private static boolean readBoolean(
            Properties properties,
            Map<String, String> environment,
            String propertyName,
            String environmentName,
            boolean defaultValue
    ) {
        String value = readString(
                properties,
                environment,
                propertyName,
                environmentName
        );
        if (value == null) {
            return defaultValue;
        }
        if ("true".equalsIgnoreCase(value)) {
            return true;
        }
        if ("false".equalsIgnoreCase(value)) {
            return false;
        }
        throw new IllegalArgumentException(
                propertyName + " must be true or false"
        );
    }

    private static String readString(
            Properties properties,
            Map<String, String> environment,
            String propertyName,
            String environmentName
    ) {
        String value = properties.getProperty(propertyName);
        if (value == null || value.isBlank()) {
            value = environment.get(environmentName);
        }
        return value == null || value.isBlank() ? null : value.trim();
    }

    private static void validateControlPlaneUri(
            URI uri,
            boolean allowInsecureHttp
    ) {
        String path = uri.getPath();
        int port = uri.getPort();
        if (!uri.isAbsolute()
                || uri.getHost() == null
                || uri.getHost().isBlank()
                || port == 0
                || uri.getUserInfo() != null
                || uri.getQuery() != null
                || uri.getFragment() != null
                || !(path == null || path.isEmpty() || "/".equals(path))) {
            throw new IllegalArgumentException(
                    "control-plane URI must be an absolute origin without "
                            + "credentials, path, query, or fragment"
            );
        }

        String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
        if ("https".equals(scheme)) {
            return;
        }
        if ("http".equals(scheme) && allowInsecureHttp) {
            return;
        }
        throw new IllegalArgumentException(
                "control-plane URI must use HTTPS; plain HTTP requires "
                        + "dns.reporting.allowInsecureHttp=true"
        );
    }

    private static void validateRange(
            int value,
            int minimum,
            int maximum,
            String field
    ) {
        if (value < minimum || value > maximum) {
            throw new IllegalArgumentException(
                    field + " must be between " + minimum + " and " + maximum
            );
        }
    }
}
