package com.ayushman.dns.server;

import java.time.Clock;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.LongAdder;

/**
 * Fixed-cardinality policy telemetry shared by the synchronization and query
 * paths. Active snapshot metadata remains owned by {@link PolicySnapshotStore}.
 */
final class PolicyTelemetry {

    private static final long DEFAULT_STALE_AFTER_MILLIS = 120_000;

    private final PolicySyncMode mode;
    private final long staleAfterMillis;
    private final Clock clock;
    private final LongAdder syncAttempts = new LongAdder();
    private final LongAdder syncActivated = new LongAdder();
    private final LongAdder syncUnchanged = new LongAdder();
    private final LongAdder syncNotModified = new LongAdder();
    private final LongAdder syncFailures = new LongAdder();
    private final LongAdder udpBlockedRequests = new LongAdder();
    private final LongAdder tcpBlockedRequests = new LongAdder();
    private final LongAdder udpUnavailableRequests = new LongAdder();
    private final LongAdder tcpUnavailableRequests = new LongAdder();
    private final AtomicReference<SyncObservation> syncObservation =
            new AtomicReference<>(SyncObservation.initial());

    static PolicyTelemetry fromConfig(PolicySyncConfig config) {
        if (config == null) {
            throw new IllegalArgumentException(
                    "policy sync config must not be null"
            );
        }
        long retryWindow = 3L * Math.max(
                config.refreshIntervalMillis(),
                config.maxBackoffMillis()
        );
        return new PolicyTelemetry(
                config.mode(),
                config.requestTimeoutMillis() + retryWindow,
                Clock.systemUTC()
        );
    }

    static PolicyTelemetry forMode(PolicySyncMode mode) {
        return new PolicyTelemetry(
                mode,
                DEFAULT_STALE_AFTER_MILLIS,
                Clock.systemUTC()
        );
    }

    PolicyTelemetry(
            PolicySyncMode mode,
            long staleAfterMillis,
            Clock clock
    ) {
        if (mode == null || clock == null) {
            throw new IllegalArgumentException(
                    "policy telemetry dependencies must not be null"
            );
        }
        if (staleAfterMillis <= 0) {
            throw new IllegalArgumentException(
                    "policy stale threshold must be positive"
            );
        }
        this.mode = mode;
        this.staleAfterMillis = staleAfterMillis;
        this.clock = clock;
    }

    PolicySyncMode mode() {
        return mode;
    }

    void recordBlocked(DnsTransport transport) {
        transportCounter(
                transport,
                udpBlockedRequests,
                tcpBlockedRequests
        ).increment();
    }

    void recordUnavailable(DnsTransport transport) {
        transportCounter(
                transport,
                udpUnavailableRequests,
                tcpUnavailableRequests
        ).increment();
    }

    void recordSyncAttempt() {
        syncAttempts.increment();
        long now = clock.instant().toEpochMilli();
        syncObservation.updateAndGet(existing -> new SyncObservation(
                now,
                existing.lastSuccessEpochMillis(),
                existing.consecutiveFailures()
        ));
    }

    void recordSyncActivated() {
        syncActivated.increment();
        recordSyncSuccess();
    }

    void recordSyncUnchanged() {
        syncUnchanged.increment();
        recordSyncSuccess();
    }

    void recordSyncNotModified() {
        syncNotModified.increment();
        recordSyncSuccess();
    }

    void recordSyncFailure() {
        syncFailures.increment();
        syncObservation.updateAndGet(existing -> new SyncObservation(
                existing.lastAttemptEpochMillis(),
                existing.lastSuccessEpochMillis(),
                existing.consecutiveFailures() == Integer.MAX_VALUE
                        ? Integer.MAX_VALUE
                        : existing.consecutiveFailures() + 1
        ));
    }

    Snapshot snapshot(
            PolicySnapshotStore.SnapshotStatus activeSnapshot
    ) {
        if (activeSnapshot == null) {
            throw new IllegalArgumentException(
                    "active policy snapshot status must not be null"
            );
        }
        if (activeSnapshot.mode() != mode) {
            throw new IllegalArgumentException(
                    "policy telemetry and snapshot modes must match"
            );
        }

        Instant now = clock.instant();
        SyncObservation sync = syncObservation.get();
        long nowEpochMillis = now.toEpochMilli();
        long publishedEpochMillis = activeSnapshot.snapshotLoaded()
                ? activeSnapshot.publishedAt().toEpochMilli()
                : 0;
        long lastAttempt = sync.lastAttemptEpochMillis();
        long lastSuccess = sync.lastSuccessEpochMillis();
        boolean stale = mode == PolicySyncMode.REQUIRED
                && activeSnapshot.snapshotLoaded()
                && lastSuccess > 0
                && elapsedMillis(nowEpochMillis, lastSuccess)
                        >= staleAfterMillis;
        SyncState syncState = syncState(
                activeSnapshot,
                sync,
                stale
        );

        return new Snapshot(
                mode,
                activeSnapshot.ready(),
                activeSnapshot.snapshotLoaded(),
                activeSnapshot.revision(),
                activeSnapshot.ruleCount(),
                toEpochSeconds(publishedEpochMillis),
                elapsedSeconds(nowEpochMillis, publishedEpochMillis),
                toEpochSeconds(lastAttempt),
                toEpochSeconds(lastSuccess),
                elapsedSeconds(nowEpochMillis, lastSuccess),
                sync.consecutiveFailures(),
                stale,
                divideRoundUp(staleAfterMillis, 1_000),
                syncState,
                syncAttempts.sum(),
                syncActivated.sum(),
                syncUnchanged.sum(),
                syncNotModified.sum(),
                syncFailures.sum(),
                udpBlockedRequests.sum(),
                tcpBlockedRequests.sum(),
                udpUnavailableRequests.sum(),
                tcpUnavailableRequests.sum()
        );
    }

    private void recordSyncSuccess() {
        long now = clock.instant().toEpochMilli();
        syncObservation.updateAndGet(existing -> new SyncObservation(
                existing.lastAttemptEpochMillis(),
                now,
                0
        ));
    }

    private SyncState syncState(
            PolicySnapshotStore.SnapshotStatus activeSnapshot,
            SyncObservation sync,
            boolean stale
    ) {
        if (mode == PolicySyncMode.DISABLED) {
            return SyncState.DISABLED;
        }
        if (!activeSnapshot.snapshotLoaded()) {
            return SyncState.AWAITING_INITIAL_SNAPSHOT;
        }
        if (stale) {
            return SyncState.STALE;
        }
        if (sync.consecutiveFailures() > 0) {
            return SyncState.DEGRADED;
        }
        return SyncState.HEALTHY;
    }

    private LongAdder transportCounter(
            DnsTransport transport,
            LongAdder udpCounter,
            LongAdder tcpCounter
    ) {
        if (transport == null) {
            throw new IllegalArgumentException("transport must not be null");
        }
        return transport == DnsTransport.UDP ? udpCounter : tcpCounter;
    }

    private static long elapsedSeconds(
            long nowEpochMillis,
            long eventEpochMillis
    ) {
        return elapsedMillis(nowEpochMillis, eventEpochMillis) / 1_000;
    }

    private static long elapsedMillis(
            long nowEpochMillis,
            long eventEpochMillis
    ) {
        if (eventEpochMillis <= 0 || nowEpochMillis <= eventEpochMillis) {
            return 0;
        }
        return nowEpochMillis - eventEpochMillis;
    }

    private static long toEpochSeconds(long epochMillis) {
        return epochMillis <= 0 ? 0 : epochMillis / 1_000;
    }

    private static long divideRoundUp(long value, long divisor) {
        return 1 + ((value - 1) / divisor);
    }

    enum SyncState {
        DISABLED,
        AWAITING_INITIAL_SNAPSHOT,
        HEALTHY,
        DEGRADED,
        STALE
    }

    record Snapshot(
            PolicySyncMode mode,
            boolean ready,
            boolean snapshotLoaded,
            long revision,
            int ruleCount,
            long publishedTimestampSeconds,
            long publishedAgeSeconds,
            long lastAttemptTimestampSeconds,
            long lastSuccessTimestampSeconds,
            long lastSuccessAgeSeconds,
            int consecutiveFailures,
            boolean stale,
            long staleAfterSeconds,
            SyncState syncState,
            long syncAttempts,
            long syncActivated,
            long syncUnchanged,
            long syncNotModified,
            long syncFailures,
            long udpBlockedRequests,
            long tcpBlockedRequests,
            long udpUnavailableRequests,
            long tcpUnavailableRequests
    ) {
        static Snapshot disabled() {
            return new Snapshot(
                    PolicySyncMode.DISABLED,
                    true,
                    false,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    false,
                    DEFAULT_STALE_AFTER_MILLIS / 1_000,
                    SyncState.DISABLED,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0
            );
        }
    }

    private record SyncObservation(
            long lastAttemptEpochMillis,
            long lastSuccessEpochMillis,
            int consecutiveFailures
    ) {
        private static SyncObservation initial() {
            return new SyncObservation(0, 0, 0);
        }
    }
}
