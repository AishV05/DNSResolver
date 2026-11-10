package com.ayushman.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.concurrent.TimeUnit;

import com.ayushman.dns.resolver.ResolverObserver;
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
        metrics.recordReceivedRequest(DnsTransport.TCP);
        metrics.recordAdmittedRequest(DnsTransport.TCP);
        metrics.recordResolvedRequest(
                DnsTransport.TCP,
                TimeUnit.MILLISECONDS.toNanos(2)
        );
        metrics.recordResolverFailure(DnsTransport.TCP);
        metrics.recordTcpConnectionAccepted();
        metrics.recordTcpConnectionClosed();
        metrics.recordMalformedRequest(DnsTransport.TCP);
        metrics.cacheLookup(ResolverObserver.CacheKind.POSITIVE, true);
        metrics.cacheLookup(ResolverObserver.CacheKind.POSITIVE, false);
        metrics.cacheLookup(ResolverObserver.CacheKind.NEGATIVE, true);
        metrics.cacheLookup(ResolverObserver.CacheKind.NEGATIVE, false);
        metrics.cacheEviction(ResolverObserver.CacheKind.POSITIVE);
        metrics.cacheEviction(ResolverObserver.CacheKind.NEGATIVE);
        metrics.upstreamResponseRejected();
        metrics.nameserverFailover();
        metrics.cnameLoopRejected();

        ServerMetrics.Snapshot snapshot = metrics.snapshot();

        assertEquals(3, snapshot.receivedRequests());
        assertEquals(2, snapshot.admittedRequests());
        assertEquals(1, snapshot.oversizedDrops());
        assertEquals(1, snapshot.rateLimitedDrops());
        assertEquals(1, snapshot.queueFullDrops());
        assertEquals(2, snapshot.malformedRequests());
        assertEquals(1, snapshot.unsupportedEdnsVersions());
        assertEquals(3, snapshot.resolvedRequests());
        assertEquals(2, snapshot.resolverFailures());
        assertEquals(
                TimeUnit.MILLISECONDS.toNanos(12),
                snapshot.totalSuccessfulHandlingNanos()
        );
        assertEquals(4.0, snapshot.averageHandledMillis());
        assertEquals(2, snapshot.udpReceivedRequests());
        assertEquals(1, snapshot.tcpReceivedRequests());
        assertEquals(1, snapshot.tcpConnectionsAccepted());
        assertEquals(0, snapshot.tcpConnectionsActive());
        assertEquals(1, snapshot.udpParserRejections());
        assertEquals(1, snapshot.tcpParserRejections());
        assertEquals(1, snapshot.positiveCacheHits());
        assertEquals(1, snapshot.positiveCacheMisses());
        assertEquals(1, snapshot.negativeCacheHits());
        assertEquals(1, snapshot.negativeCacheMisses());
        assertEquals(1, snapshot.positiveCacheEvictions());
        assertEquals(1, snapshot.negativeCacheEvictions());
        assertEquals(1, snapshot.upstreamResponseRejections());
        assertEquals(1, snapshot.nameserverFailovers());
        assertEquals(1, snapshot.cnameLoopRejections());
    }
}
