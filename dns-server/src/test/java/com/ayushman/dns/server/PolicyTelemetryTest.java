package com.ayushman.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;

import com.ayushman.dns.policy.DnsPolicyAction;
import com.ayushman.dns.policy.DnsPolicyMatchType;
import com.ayushman.dns.policy.DnsPolicyRule;
import com.ayushman.dns.policy.DnsPolicySnapshot;
import org.junit.jupiter.api.Test;

class PolicyTelemetryTest {

    @Test
    void distinguishesDisabledFromAnUnloadedRequiredPolicy() {
        MutableClock clock = new MutableClock("2026-10-05T00:00:00Z");
        PolicySnapshotStore disabledStore = new PolicySnapshotStore(
                PolicySyncMode.DISABLED
        );
        PolicyTelemetry disabled = new PolicyTelemetry(
                PolicySyncMode.DISABLED,
                60_000,
                clock
        );
        PolicyTelemetry.Snapshot disabledSnapshot = disabled.snapshot(
                disabledStore.snapshotStatus()
        );

        assertTrue(disabledSnapshot.ready());
        assertFalse(disabledSnapshot.snapshotLoaded());
        assertEquals(
                PolicyTelemetry.SyncState.DISABLED,
                disabledSnapshot.syncState()
        );

        PolicySnapshotStore requiredStore = new PolicySnapshotStore(
                PolicySyncMode.REQUIRED
        );
        PolicyTelemetry required = new PolicyTelemetry(
                PolicySyncMode.REQUIRED,
                60_000,
                clock
        );
        PolicyTelemetry.Snapshot waiting = required.snapshot(
                requiredStore.snapshotStatus()
        );

        assertFalse(waiting.ready());
        assertFalse(waiting.snapshotLoaded());
        assertEquals(
                PolicyTelemetry.SyncState.AWAITING_INITIAL_SNAPSHOT,
                waiting.syncState()
        );
        assertEquals(0, waiting.revision());
    }

    @Test
    void reportsAtomicSnapshotMetadataAndClampsFuturePublicationAge() {
        MutableClock clock = new MutableClock("2026-10-05T00:00:00Z");
        PolicySnapshotStore store = new PolicySnapshotStore(
                PolicySyncMode.REQUIRED
        );
        store.activate(new DnsPolicySnapshot(
                0,
                Instant.parse("2026-10-05T00:01:00Z"),
                List.of(rule("one.example"), rule("two.example"))
        ));
        PolicyTelemetry telemetry = new PolicyTelemetry(
                PolicySyncMode.REQUIRED,
                60_000,
                clock
        );
        PolicyTelemetry.Snapshot snapshot = telemetry.snapshot(
                store.snapshotStatus()
        );

        assertTrue(snapshot.ready());
        assertTrue(snapshot.snapshotLoaded());
        assertEquals(0, snapshot.revision());
        assertEquals(2, snapshot.ruleCount());
        assertEquals(0, snapshot.publishedAgeSeconds());
    }

    @Test
    void tracksSyncFreshnessResultsFailuresAndRecovery() {
        MutableClock clock = new MutableClock("2026-10-05T00:00:00Z");
        PolicySnapshotStore store = new PolicySnapshotStore(
                PolicySyncMode.REQUIRED
        );
        store.activate(new DnsPolicySnapshot(
                7,
                clock.instant(),
                List.of(rule("blocked.example"))
        ));
        PolicyTelemetry telemetry = new PolicyTelemetry(
                PolicySyncMode.REQUIRED,
                60_000,
                clock
        );

        telemetry.recordSyncAttempt();
        telemetry.recordSyncActivated();
        clock.advanceSeconds(10);
        telemetry.recordSyncAttempt();
        telemetry.recordSyncFailure();

        PolicyTelemetry.Snapshot degraded = telemetry.snapshot(
                store.snapshotStatus()
        );
        assertTrue(degraded.ready());
        assertEquals(2, degraded.syncAttempts());
        assertEquals(1, degraded.syncActivated());
        assertEquals(1, degraded.syncFailures());
        assertEquals(1, degraded.consecutiveFailures());
        assertEquals(
                PolicyTelemetry.SyncState.DEGRADED,
                degraded.syncState()
        );
        assertFalse(degraded.stale());

        clock.advanceSeconds(50);
        PolicyTelemetry.Snapshot stale = telemetry.snapshot(
                store.snapshotStatus()
        );
        assertTrue(stale.ready());
        assertTrue(stale.stale());
        assertEquals(PolicyTelemetry.SyncState.STALE, stale.syncState());

        telemetry.recordSyncAttempt();
        telemetry.recordSyncNotModified();
        PolicyTelemetry.Snapshot recovered = telemetry.snapshot(
                store.snapshotStatus()
        );
        assertFalse(recovered.stale());
        assertEquals(0, recovered.consecutiveFailures());
        assertEquals(
                PolicyTelemetry.SyncState.HEALTHY,
                recovered.syncState()
        );
        assertEquals(1, recovered.syncNotModified());
        assertEquals(0, recovered.lastSuccessAgeSeconds());
    }

    @Test
    void recordsOnlyFixedTransportPolicyDecisionSeries() {
        MutableClock clock = new MutableClock("2026-10-05T00:00:00Z");
        PolicyTelemetry telemetry = new PolicyTelemetry(
                PolicySyncMode.REQUIRED,
                60_000,
                clock
        );
        PolicySnapshotStore store = new PolicySnapshotStore(
                PolicySyncMode.REQUIRED
        );

        telemetry.recordBlocked(DnsTransport.UDP);
        telemetry.recordBlocked(DnsTransport.TCP);
        telemetry.recordUnavailable(DnsTransport.TCP);

        PolicyTelemetry.Snapshot snapshot = telemetry.snapshot(
                store.snapshotStatus()
        );
        assertEquals(1, snapshot.udpBlockedRequests());
        assertEquals(1, snapshot.tcpBlockedRequests());
        assertEquals(0, snapshot.udpUnavailableRequests());
        assertEquals(1, snapshot.tcpUnavailableRequests());
    }

    private DnsPolicyRule rule(String domain) {
        return new DnsPolicyRule(
                domain,
                DnsPolicyMatchType.EXACT,
                DnsPolicyAction.BLOCK
        );
    }

    private static final class MutableClock extends Clock {

        private Instant instant;

        private MutableClock(String instant) {
            this.instant = Instant.parse(instant);
        }

        private void advanceSeconds(long seconds) {
            instant = instant.plusSeconds(seconds);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            if (zone == null) {
                throw new IllegalArgumentException("zone must not be null");
            }
            return this;
        }

        @Override
        public Instant instant() {
            return instant;
        }
    }
}
