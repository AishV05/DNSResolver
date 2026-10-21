package com.ayushman.dns.server;

import java.net.URI;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

/**
 * Bounded configuration for the control-plane snapshot polling loop.
 *
 * <p>Policy synchronization is disabled by default. Required mode needs an
 * explicit endpoint and an absolute token-file path. Plain HTTP is rejected
 * unless an operator explicitly opts into it for an isolated trusted
 * network.</p>
 */
public record PolicySyncConfig(
        PolicySyncMode mode,
        URI snapshotUri,
        Path tokenFile,
        boolean allowInsecureHttp,
        int connectTimeoutMillis,
        int requestTimeoutMillis,
        int refreshIntervalMillis,
        int initialBackoffMillis,
        int maxBackoffMillis,
        int maxResponseBytes,
        int maxRules
) {

    private static final String SNAPSHOT_PATH =
            "/api/v1/internal/policy-snapshot";
    private static final int DEFAULT_CONNECT_TIMEOUT_MILLIS = 2_000;
    private static final int DEFAULT_REQUEST_TIMEOUT_MILLIS = 5_000;
    private static final int DEFAULT_REFRESH_INTERVAL_MILLIS = 30_000;
    private static final int DEFAULT_INITIAL_BACKOFF_MILLIS = 1_000;
    private static final int DEFAULT_MAX_BACKOFF_MILLIS = 30_000;
    private static final int DEFAULT_MAX_RESPONSE_BYTES = 1_048_576;
    private static final int DEFAULT_MAX_RULES = 10_000;

    public PolicySyncConfig {
        if (mode == null) {
            throw new IllegalArgumentException("policy mode must not be null");
        }

        validateRange(
                connectTimeoutMillis,
                100,
                60_000,
                "connectTimeoutMillis"
        );
        validateRange(
                requestTimeoutMillis,
                100,
                120_000,
                "requestTimeoutMillis"
        );
        if (requestTimeoutMillis < connectTimeoutMillis) {
            throw new IllegalArgumentException(
                    "requestTimeoutMillis must not be less than "
                            + "connectTimeoutMillis"
            );
        }
        validateRange(
                refreshIntervalMillis,
                100,
                3_600_000,
                "refreshIntervalMillis"
        );
        validateRange(
                initialBackoffMillis,
                100,
                3_600_000,
                "initialBackoffMillis"
        );
        validateRange(
                maxBackoffMillis,
                100,
                3_600_000,
                "maxBackoffMillis"
        );
        if (initialBackoffMillis > maxBackoffMillis) {
            throw new IllegalArgumentException(
                    "initialBackoffMillis must not exceed maxBackoffMillis"
            );
        }
        validateRange(
                maxResponseBytes,
                256,
                16 * 1_024 * 1_024,
                "maxResponseBytes"
        );
        validateRange(maxRules, 1, 100_000, "maxRules");

        if (snapshotUri != null) {
            validateSnapshotUri(snapshotUri, allowInsecureHttp);
        }
        if (tokenFile != null && !tokenFile.isAbsolute()) {
            throw new IllegalArgumentException(
                    "policy token file must be an absolute path"
            );
        }
        if (mode == PolicySyncMode.REQUIRED) {
            if (snapshotUri == null) {
                throw new IllegalArgumentException(
                        "policy snapshot URI is required in REQUIRED mode"
                );
            }
            if (tokenFile == null) {
                throw new IllegalArgumentException(
                        "policy token file is required in REQUIRED mode"
                );
            }
        }
    }

    public static PolicySyncConfig fromSystem() {
        return from(System.getProperties(), System.getenv());
    }

    static PolicySyncConfig defaults() {
        return new PolicySyncConfig(
                PolicySyncMode.DISABLED,
                null,
                null,
                false,
                DEFAULT_CONNECT_TIMEOUT_MILLIS,
                DEFAULT_REQUEST_TIMEOUT_MILLIS,
                DEFAULT_REFRESH_INTERVAL_MILLIS,
                DEFAULT_INITIAL_BACKOFF_MILLIS,
                DEFAULT_MAX_BACKOFF_MILLIS,
                DEFAULT_MAX_RESPONSE_BYTES,
                DEFAULT_MAX_RULES
        );
    }

    static PolicySyncConfig from(
            Properties properties,
            Map<String, String> environment
    ) {
        if (properties == null || environment == null) {
            throw new IllegalArgumentException(
                    "properties and environment must not be null"
            );
        }

        PolicySyncMode mode = readMode(properties, environment);
        String uriValue = readString(
                properties,
                environment,
                "dns.policy.snapshotUrl",
                "DNS_POLICY_SNAPSHOT_URL"
        );
        String tokenFileValue = readString(
                properties,
                environment,
                "dns.policy.tokenFile",
                "DNS_POLICY_TOKEN_FILE"
        );

        return new PolicySyncConfig(
                mode,
                parseUri(uriValue),
                parsePath(tokenFileValue),
                readBoolean(
                        properties,
                        environment,
                        "dns.policy.allowInsecureHttp",
                        "DNS_POLICY_ALLOW_INSECURE_HTTP",
                        false
                ),
                readInt(
                        properties,
                        environment,
                        "dns.policy.connectTimeoutMillis",
                        "DNS_POLICY_CONNECT_TIMEOUT_MILLIS",
                        DEFAULT_CONNECT_TIMEOUT_MILLIS
                ),
                readInt(
                        properties,
                        environment,
                        "dns.policy.requestTimeoutMillis",
                        "DNS_POLICY_REQUEST_TIMEOUT_MILLIS",
                        DEFAULT_REQUEST_TIMEOUT_MILLIS
                ),
                readInt(
                        properties,
                        environment,
                        "dns.policy.refreshIntervalMillis",
                        "DNS_POLICY_REFRESH_INTERVAL_MILLIS",
                        DEFAULT_REFRESH_INTERVAL_MILLIS
                ),
                readInt(
                        properties,
                        environment,
                        "dns.policy.initialBackoffMillis",
                        "DNS_POLICY_INITIAL_BACKOFF_MILLIS",
                        DEFAULT_INITIAL_BACKOFF_MILLIS
                ),
                readInt(
                        properties,
                        environment,
                        "dns.policy.maxBackoffMillis",
                        "DNS_POLICY_MAX_BACKOFF_MILLIS",
                        DEFAULT_MAX_BACKOFF_MILLIS
                ),
                readInt(
                        properties,
                        environment,
                        "dns.policy.maxResponseBytes",
                        "DNS_POLICY_MAX_RESPONSE_BYTES",
                        DEFAULT_MAX_RESPONSE_BYTES
                ),
                readInt(
                        properties,
                        environment,
                        "dns.policy.maxRules",
                        "DNS_POLICY_MAX_RULES",
                        DEFAULT_MAX_RULES
                )
        );
    }

    private static PolicySyncMode readMode(
            Properties properties,
            Map<String, String> environment
    ) {
        String value = readString(
                properties,
                environment,
                "dns.policy.mode",
                "DNS_POLICY_MODE"
        );
        if (value == null) {
            return PolicySyncMode.DISABLED;
        }
        try {
            return PolicySyncMode.valueOf(
                    value.trim().toUpperCase(Locale.ROOT)
            );
        } catch (IllegalArgumentException invalidMode) {
            throw new IllegalArgumentException(
                    "dns.policy.mode must be DISABLED or REQUIRED",
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
                    "dns.policy.snapshotUrl must be a valid URI",
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
                    "dns.policy.tokenFile must be a valid path",
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

    private static void validateSnapshotUri(
            URI uri,
            boolean allowInsecureHttp
    ) {
        if (!uri.isAbsolute()
                || uri.getHost() == null
                || uri.getHost().isBlank()
                || uri.getUserInfo() != null
                || uri.getQuery() != null
                || uri.getFragment() != null
                || !SNAPSHOT_PATH.equals(uri.getPath())) {
            throw new IllegalArgumentException(
                    "policy snapshot URI must be an absolute endpoint at "
                            + SNAPSHOT_PATH
                            + " without user-info, query, or fragment"
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
                "policy snapshot URI must use HTTPS; plain HTTP requires "
                        + "dns.policy.allowInsecureHttp=true"
        );
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
}
