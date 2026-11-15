package com.ayushman.dns.admin.fleet;

import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.LongAdder;

import org.springframework.stereotype.Component;

/** Process-local aggregate cleanup telemetry; it contains no resolver identity. */
@Component
class ResolverSessionRetentionTelemetry {

    private final LongAdder successfulRuns = new LongAdder();
    private final LongAdder failedRuns = new LongAdder();
    private final LongAdder deletedSessions = new LongAdder();
    private final AtomicLong lastSuccessEpochMillis = new AtomicLong();
    private final AtomicInteger consecutiveFailures = new AtomicInteger();
    private final AtomicInteger saturated = new AtomicInteger();

    void recordSuccess(int deleted, Instant completedAt, boolean wasSaturated) {
        successfulRuns.increment();
        deletedSessions.add(deleted);
        lastSuccessEpochMillis.set(completedAt.toEpochMilli());
        consecutiveFailures.set(0);
        saturated.set(wasSaturated ? 1 : 0);
    }

    void recordFailure() {
        failedRuns.increment();
        consecutiveFailures.updateAndGet(current ->
                current == Integer.MAX_VALUE ? current : current + 1
        );
    }

    Snapshot snapshot() {
        return new Snapshot(
                successfulRuns.sum(),
                failedRuns.sum(),
                deletedSessions.sum(),
                lastSuccessEpochMillis.get(),
                consecutiveFailures.get(),
                saturated.get() == 1
        );
    }

    record Snapshot(
            long successfulRuns,
            long failedRuns,
            long deletedSessions,
            long lastSuccessEpochMillis,
            int consecutiveFailures,
            boolean saturated
    ) {
    }
}

