package com.ayushman.dns.server;

import java.util.concurrent.atomic.LongAdder;

import com.ayushman.dns.resolver.ResolverObserver;

/**
 * Thread-safe, fixed-cardinality counters for both DNS transports.
 */
public final class ServerMetrics implements ResolverObserver {

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
    private final LongAdder udpReceivedRequests = new LongAdder();
    private final LongAdder tcpReceivedRequests = new LongAdder();
    private final LongAdder udpAdmittedRequests = new LongAdder();
    private final LongAdder tcpAdmittedRequests = new LongAdder();
    private final LongAdder udpResolvedRequests = new LongAdder();
    private final LongAdder tcpResolvedRequests = new LongAdder();
    private final LongAdder udpResolverFailures = new LongAdder();
    private final LongAdder tcpResolverFailures = new LongAdder();
    private final LongAdder tcpConnectionsAccepted = new LongAdder();
    private final LongAdder tcpConnectionsActive = new LongAdder();
    private final LongAdder tcpConnectionLimitRejections = new LongAdder();
    private final LongAdder tcpConnectionQueueRejections = new LongAdder();
    private final LongAdder tcpConnectionTimeouts = new LongAdder();
    private final LongAdder tcpProtocolErrors = new LongAdder();
    private final LongAdder udpParserRejections = new LongAdder();
    private final LongAdder tcpParserRejections = new LongAdder();
    private final LongAdder positiveCacheHits = new LongAdder();
    private final LongAdder positiveCacheMisses = new LongAdder();
    private final LongAdder negativeCacheHits = new LongAdder();
    private final LongAdder negativeCacheMisses = new LongAdder();
    private final LongAdder positiveCacheEvictions = new LongAdder();
    private final LongAdder negativeCacheEvictions = new LongAdder();
    private final LongAdder upstreamResponseRejections = new LongAdder();
    private final LongAdder nameserverFailovers = new LongAdder();
    private final LongAdder cnameLoopRejections = new LongAdder();

    void recordReceivedRequest() {
        recordReceivedRequest(DnsTransport.UDP);
    }

    void recordReceivedRequest(
            DnsTransport transport
    ) {
        receivedRequests.increment();
        transportCounter(
                transport,
                udpReceivedRequests,
                tcpReceivedRequests
        ).increment();
    }

    void recordAdmittedRequest() {
        recordAdmittedRequest(DnsTransport.UDP);
    }

    void recordAdmittedRequest(
            DnsTransport transport
    ) {
        admittedRequests.increment();
        transportCounter(
                transport,
                udpAdmittedRequests,
                tcpAdmittedRequests
        ).increment();
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
        recordMalformedRequest(DnsTransport.UDP);
    }

    void recordMalformedRequest(
            DnsTransport transport
    ) {
        malformedRequests.increment();
        transportCounter(
                transport,
                udpParserRejections,
                tcpParserRejections
        ).increment();
    }

    void recordUnsupportedEdnsVersion() {
        recordUnsupportedEdnsVersion(DnsTransport.UDP);
    }

    void recordUnsupportedEdnsVersion(
            DnsTransport transport
    ) {
        unsupportedEdnsVersions.increment();
    }

    void recordResolvedRequest(
            long handledNanos
    ) {
        recordResolvedRequest(DnsTransport.UDP, handledNanos);
    }

    void recordResolvedRequest(
            DnsTransport transport,
            long handledNanos
    ) {

        resolvedRequests.increment();
        transportCounter(
                transport,
                udpResolvedRequests,
                tcpResolvedRequests
        ).increment();
        totalHandledNanos.add(Math.max(0, handledNanos));
    }

    void recordResolverFailure() {
        recordResolverFailure(DnsTransport.UDP);
    }

    void recordResolverFailure(
            DnsTransport transport
    ) {
        resolverFailures.increment();
        transportCounter(
                transport,
                udpResolverFailures,
                tcpResolverFailures
        ).increment();
    }

    void recordTcpConnectionAccepted() {
        tcpConnectionsAccepted.increment();
        tcpConnectionsActive.increment();
    }

    void recordTcpConnectionClosed() {
        tcpConnectionsActive.decrement();
    }

    void recordTcpConnectionLimitRejection() {
        tcpConnectionLimitRejections.increment();
    }

    void recordTcpConnectionQueueRejection() {
        tcpConnectionQueueRejections.increment();
    }

    void recordTcpConnectionTimeout() {
        tcpConnectionTimeouts.increment();
    }

    void recordTcpProtocolError() {
        tcpProtocolErrors.increment();
    }

    @Override
    public void cacheLookup(CacheKind cache, boolean hit) {
        if (cache == null) {
            throw new IllegalArgumentException("cache must not be null");
        }
        if (cache == CacheKind.POSITIVE) {
            (hit ? positiveCacheHits : positiveCacheMisses).increment();
        } else {
            (hit ? negativeCacheHits : negativeCacheMisses).increment();
        }
    }

    @Override
    public void cacheEviction(CacheKind cache) {
        if (cache == null) {
            throw new IllegalArgumentException("cache must not be null");
        }
        (cache == CacheKind.POSITIVE
                ? positiveCacheEvictions
                : negativeCacheEvictions).increment();
    }

    @Override
    public void upstreamResponseRejected() {
        upstreamResponseRejections.increment();
    }

    @Override
    public void nameserverFailover() {
        nameserverFailovers.increment();
    }

    @Override
    public void cnameLoopRejected() {
        cnameLoopRejections.increment();
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
                handledNanos,
                averageHandledMillis,
                udpReceivedRequests.sum(),
                tcpReceivedRequests.sum(),
                udpAdmittedRequests.sum(),
                tcpAdmittedRequests.sum(),
                udpResolvedRequests.sum(),
                tcpResolvedRequests.sum(),
                udpResolverFailures.sum(),
                tcpResolverFailures.sum(),
                tcpConnectionsAccepted.sum(),
                Math.max(0, tcpConnectionsActive.sum()),
                tcpConnectionLimitRejections.sum(),
                tcpConnectionQueueRejections.sum(),
                tcpConnectionTimeouts.sum(),
                tcpProtocolErrors.sum(),
                udpParserRejections.sum(),
                tcpParserRejections.sum(),
                positiveCacheHits.sum(),
                positiveCacheMisses.sum(),
                negativeCacheHits.sum(),
                negativeCacheMisses.sum(),
                positiveCacheEvictions.sum(),
                negativeCacheEvictions.sum(),
                upstreamResponseRejections.sum(),
                nameserverFailovers.sum(),
                cnameLoopRejections.sum()
        );
    }

    private LongAdder transportCounter(
            DnsTransport transport,
            LongAdder udpCounter,
            LongAdder tcpCounter
    ) {
        if (transport == null) {
            throw new IllegalArgumentException("transport must not be null");
        }

        return transport == DnsTransport.UDP
                ? udpCounter
                : tcpCounter;
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
            long totalSuccessfulHandlingNanos,
            double averageHandledMillis,
            long udpReceivedRequests,
            long tcpReceivedRequests,
            long udpAdmittedRequests,
            long tcpAdmittedRequests,
            long udpResolvedRequests,
            long tcpResolvedRequests,
            long udpResolverFailures,
            long tcpResolverFailures,
            long tcpConnectionsAccepted,
            long tcpConnectionsActive,
            long tcpConnectionLimitRejections,
            long tcpConnectionQueueRejections,
            long tcpConnectionTimeouts,
            long tcpProtocolErrors,
            long udpParserRejections,
            long tcpParserRejections,
            long positiveCacheHits,
            long positiveCacheMisses,
            long negativeCacheHits,
            long negativeCacheMisses,
            long positiveCacheEvictions,
            long negativeCacheEvictions,
            long upstreamResponseRejections,
            long nameserverFailovers,
            long cnameLoopRejections
    ) {
    }
}
