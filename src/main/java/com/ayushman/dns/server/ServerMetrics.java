package com.ayushman.dns.server;

import java.util.concurrent.atomic.LongAdder;

/**
 * Thread-safe counters for observing the UDP server at runtime.
 */
public final class ServerMetrics {

    private final LongAdder receivedRequests = new LongAdder();
    private final LongAdder admittedRequests = new LongAdder();
    private final LongAdder oversizedDrops = new LongAdder();
    private final LongAdder rateLimitedDrops = new LongAdder();
    private final LongAdder queueFullDrops = new LongAdder();
    private final LongAdder malformedRequests = new LongAdder();
    private final LongAdder unsupportedEdnsVersions = new LongAdder();
    private final LongAdder resolvedRequests = new LongAdder();
    private final LongAdder resolverFailures = new LongAdder();
    private final LongAdder totalHandledNanos = new LongAdder();

    void recordReceivedRequest() {
        receivedRequests.increment();
    }

    void recordAdmittedRequest() {
        admittedRequests.increment();
    }

    void recordOversizedDrop() {
        oversizedDrops.increment();
    }

    void recordRateLimitedDrop() {
        rateLimitedDrops.increment();
    }

    void recordQueueFullDrop() {
        queueFullDrops.increment();
    }

    void recordMalformedRequest() {
        malformedRequests.increment();
    }

    void recordUnsupportedEdnsVersion() {
        unsupportedEdnsVersions.increment();
    }

    void recordResolvedRequest(
            long handledNanos
    ) {

        resolvedRequests.increment();
        totalHandledNanos.add(Math.max(0, handledNanos));
    }

    void recordResolverFailure() {
        resolverFailures.increment();
    }

    public Snapshot snapshot() {
        long resolved = resolvedRequests.sum();
        long handledNanos = totalHandledNanos.sum();

        double averageHandledMillis = resolved == 0
                ? 0
                : handledNanos / (double) resolved / 1_000_000;

        return new Snapshot(
                receivedRequests.sum(),
                admittedRequests.sum(),
                oversizedDrops.sum(),
                rateLimitedDrops.sum(),
                queueFullDrops.sum(),
                malformedRequests.sum(),
                unsupportedEdnsVersions.sum(),
                resolved,
                resolverFailures.sum(),
                averageHandledMillis
        );
    }

    public record Snapshot(
            long receivedRequests,
            long admittedRequests,
            long oversizedDrops,
            long rateLimitedDrops,
            long queueFullDrops,
            long malformedRequests,
            long unsupportedEdnsVersions,
            long resolvedRequests,
            long resolverFailures,
            double averageHandledMillis
    ) {
    }
}
