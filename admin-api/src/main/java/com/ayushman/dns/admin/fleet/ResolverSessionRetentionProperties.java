package com.ayushman.dns.admin.fleet;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** Bounded settings for retaining detailed, superseded resolver sessions. */
@ConfigurationProperties(prefix = "dns.admin.fleet.session-retention")
public record ResolverSessionRetentionProperties(
        boolean enabled,
        long retentionMillis,
        long cleanupIntervalMillis,
        int cleanupBatchSize,
        int cleanupMaxBatchesPerRun
) {

    static final long MINIMUM_RETENTION_MILLIS = 86_400_000L;
    static final long MAXIMUM_RETENTION_MILLIS = 315_360_000_000L;
    static final long MINIMUM_INTERVAL_MILLIS = 60_000L;
    static final long MAXIMUM_INTERVAL_MILLIS = 86_400_000L;
    static final int MAXIMUM_BATCH_SIZE = 5_000;
    static final int MAXIMUM_BATCHES_PER_RUN = 100;

    public ResolverSessionRetentionProperties {
        if (retentionMillis < MINIMUM_RETENTION_MILLIS
                || retentionMillis > MAXIMUM_RETENTION_MILLIS) {
            throw new IllegalArgumentException(
                    "dns.admin.fleet.session-retention.retention-millis must be between "
                            + MINIMUM_RETENTION_MILLIS
                            + " and "
                            + MAXIMUM_RETENTION_MILLIS
            );
        }
        if (cleanupIntervalMillis < MINIMUM_INTERVAL_MILLIS
                || cleanupIntervalMillis > MAXIMUM_INTERVAL_MILLIS) {
            throw new IllegalArgumentException(
                    "dns.admin.fleet.session-retention.cleanup-interval-millis must be between "
                            + MINIMUM_INTERVAL_MILLIS
                            + " and "
                            + MAXIMUM_INTERVAL_MILLIS
            );
        }
        if (cleanupIntervalMillis >= retentionMillis) {
            throw new IllegalArgumentException(
                    "dns.admin.fleet.session-retention.cleanup-interval-millis must be less than retention-millis"
            );
        }
        if (cleanupBatchSize < 1 || cleanupBatchSize > MAXIMUM_BATCH_SIZE) {
            throw new IllegalArgumentException(
                    "dns.admin.fleet.session-retention.cleanup-batch-size must be between 1 and "
                            + MAXIMUM_BATCH_SIZE
            );
        }
        if (cleanupMaxBatchesPerRun < 1
                || cleanupMaxBatchesPerRun > MAXIMUM_BATCHES_PER_RUN) {
            throw new IllegalArgumentException(
                    "dns.admin.fleet.session-retention.cleanup-max-batches-per-run must be between 1 and "
                            + MAXIMUM_BATCHES_PER_RUN
            );
        }
    }
}

