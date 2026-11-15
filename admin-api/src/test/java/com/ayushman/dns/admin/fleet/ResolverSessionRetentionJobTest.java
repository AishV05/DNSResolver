package com.ayushman.dns.admin.fleet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import org.junit.jupiter.api.Test;

class ResolverSessionRetentionJobTest {

    private static final Instant NOW = Instant.parse("2026-11-15T12:00:00Z");

    @Test
    void recordsSuccessfulBoundedCleanupAndSaturation() {
        ResolverSessionPruner pruner = mock(ResolverSessionPruner.class);
        ResolverSessionRetentionTelemetry telemetry =
                new ResolverSessionRetentionTelemetry();
        ResolverSessionRetentionProperties properties = properties(2);
        when(pruner.pruneBatch(any(), eq(2))).thenReturn(2, 1);
        when(pruner.hasEligibleSessions(any())).thenReturn(false);

        new ResolverSessionRetentionJob(
                pruner,
                properties,
                telemetry,
                Clock.fixed(NOW, ZoneOffset.UTC)
        ).runCleanup();

        ResolverSessionRetentionTelemetry.Snapshot state = telemetry.snapshot();
        assertThat(state.successfulRuns()).isEqualTo(1);
        assertThat(state.failedRuns()).isZero();
        assertThat(state.deletedSessions()).isEqualTo(3);
        assertThat(state.lastSuccessEpochMillis()).isEqualTo(NOW.toEpochMilli());
        assertThat(state.consecutiveFailures()).isZero();
        assertThat(state.saturated()).isFalse();
    }

    @Test
    void recordsFailureAndAllowsTheNextRunToRecover() {
        ResolverSessionPruner pruner = mock(ResolverSessionPruner.class);
        ResolverSessionRetentionTelemetry telemetry =
                new ResolverSessionRetentionTelemetry();
        when(pruner.pruneBatch(any(), eq(2)))
                .thenThrow(new IllegalStateException("database unavailable"))
                .thenReturn(0);
        when(pruner.hasEligibleSessions(any())).thenReturn(false);
        ResolverSessionRetentionJob job = new ResolverSessionRetentionJob(
                pruner,
                properties(2),
                telemetry,
                Clock.fixed(NOW, ZoneOffset.UTC)
        );

        job.runCleanup();
        assertThat(telemetry.snapshot().failedRuns()).isEqualTo(1);
        assertThat(telemetry.snapshot().consecutiveFailures()).isEqualTo(1);

        job.runCleanup();
        assertThat(telemetry.snapshot().successfulRuns()).isEqualTo(1);
        assertThat(telemetry.snapshot().consecutiveFailures()).isZero();
    }

    private ResolverSessionRetentionProperties properties(int batchSize) {
        return new ResolverSessionRetentionProperties(
                true,
                86_400_000L,
                60_000L,
                batchSize,
                2
        );
    }
}

