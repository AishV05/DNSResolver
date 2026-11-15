package com.ayushman.dns.admin.fleet;

import java.time.Clock;
import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/** Bounded scheduled cleanup of detailed superseded-session rows. */
@Component
@ConditionalOnProperty(
        prefix = "dns.admin.fleet.session-retention",
        name = "enabled",
        havingValue = "true",
        matchIfMissing = true
)
class ResolverSessionRetentionJob {

    private static final Logger LOGGER = LoggerFactory.getLogger(
            ResolverSessionRetentionJob.class
    );

    private final ResolverSessionPruner pruner;
    private final ResolverSessionRetentionProperties properties;
    private final ResolverSessionRetentionTelemetry telemetry;
    private final Clock clock;

    ResolverSessionRetentionJob(
            ResolverSessionPruner pruner,
            ResolverSessionRetentionProperties properties,
            ResolverSessionRetentionTelemetry telemetry,
            Clock clock
    ) {
        this.pruner = pruner;
        this.properties = properties;
        this.telemetry = telemetry;
        this.clock = clock;
    }

    @Scheduled(
            initialDelay = 0,
            fixedDelayString = "${dns.admin.fleet.session-retention.cleanup-interval-millis:3600000}"
    )
    void runCleanup() {
        Instant cutoff = clock.instant().minusMillis(properties.retentionMillis());
        int totalDeleted = 0;
        try {
            for (int batch = 0;
                    batch < properties.cleanupMaxBatchesPerRun();
                    batch++) {
                int deleted = pruner.pruneBatch(
                        cutoff,
                        properties.cleanupBatchSize()
                );
                totalDeleted = Math.addExact(totalDeleted, deleted);
                if (deleted < properties.cleanupBatchSize()) {
                    break;
                }
            }
            boolean saturated = pruner.hasEligibleSessions(cutoff);
            telemetry.recordSuccess(totalDeleted, clock.instant(), saturated);
            if (totalDeleted > 0 || saturated) {
                LOGGER.info(
                        "Resolver session cleanup deleted {} detailed rows; backlog remains={}",
                        totalDeleted,
                        saturated
                );
            }
        } catch (RuntimeException exception) {
            telemetry.recordFailure();
            LOGGER.warn(
                    "Resolver session cleanup failed; detailed history was left intact"
            );
        }
    }
}

