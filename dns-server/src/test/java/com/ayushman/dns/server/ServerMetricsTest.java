package com.ayushman.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;

public class ServerMetricsTest {

    @Test
    void shouldExposeAConsistentMetricsSnapshot() {

        ServerMetrics metrics = new ServerMetrics();

        metrics.recordReceivedRequest();
        metrics.recordReceivedRequest();
        metrics.recordAdmittedRequest();
        metrics.recordOversizedDrop();
        metrics.recordRateLimitedDrop();
        metrics.recordQueueFullDrop();
        metrics.recordMalformedRequest();
        metrics.recordUnsupportedEdnsVersion();
        metrics.recordResolvedRequest(
                TimeUnit.MILLISECONDS.toNanos(4)
        );
        metrics.recordResolvedRequest(
                TimeUnit.MILLISECONDS.toNanos(6)
        );
        metrics.recordResolverFailure();

        ServerMetrics.Snapshot snapshot = metrics.snapshot();

        assertEquals(2, snapshot.receivedRequests());
        assertEquals(1, snapshot.admittedRequests());
        assertEquals(1, snapshot.oversizedDrops());
        assertEquals(1, snapshot.rateLimitedDrops());
        assertEquals(1, snapshot.queueFullDrops());
        assertEquals(1, snapshot.malformedRequests());
        assertEquals(1, snapshot.unsupportedEdnsVersions());
        assertEquals(2, snapshot.resolvedRequests());
        assertEquals(1, snapshot.resolverFailures());
        assertEquals(5.0, snapshot.averageHandledMillis());
    }
}
