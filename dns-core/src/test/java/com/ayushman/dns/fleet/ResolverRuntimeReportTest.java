package com.ayushman.dns.fleet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Test;

class ResolverRuntimeReportTest {

    private static final UUID SESSION_ID =
            UUID.fromString("0aefb223-6f13-4c73-8259-b1cbe8ff4a91");
    private static final UUID BOOT_ID =
            UUID.fromString("ca7a8e37-a50f-4bca-b66a-e44fc8a79898");
    private static final UUID NIL_UUID = new UUID(0, 0);

    @Test
    void keepsFleetPolicyStateVocabularyExplicit() {
        assertEquals(
                List.of(
                        "DATA_PLANE_UNOBSERVED",
                        "DATA_PLANE_NOT_CONVERGED",
                        "DATA_PLANE_CONVERGED"
                ),
                Arrays.stream(ResolverFleetPolicyState.values())
                        .map(Enum::name)
                        .toList()
        );
    }

    @Test
    void keepsPolicyModeAndSyncStateVocabulariesExplicit() {
        assertEquals(
                List.of("DISABLED", "REQUIRED"),
                Arrays.stream(ResolverPolicyMode.values())
                        .map(Enum::name)
                        .toList()
        );
        assertEquals(
                List.of(
                        "DISABLED",
                        "AWAITING_INITIAL_SNAPSHOT",
                        "HEALTHY",
                        "DEGRADED",
                        "STALE"
                ),
                Arrays.stream(ResolverPolicySyncState.values())
                        .map(Enum::name)
                        .toList()
        );
    }

    @Test
    void acceptsDisabledPolicyState() {
        ResolverRuntimeReport report = report(
                ResolverPolicyMode.DISABLED,
                false,
                0,
                0,
                true,
                ResolverPolicySyncState.DISABLED
        );

        assertEquals(1, report.schemaVersion());
        assertEquals(SESSION_ID, report.sessionId());
        assertEquals(BOOT_ID, report.bootId());
        assertEquals(4, report.sessionGeneration());
        assertEquals(9, report.sequence());
        assertEquals("0.1.0-SNAPSHOT", report.applicationVersion());
        assertTrue(report.policyReady());
        assertFalse(report.policySnapshotLoaded());
    }

    @Test
    void acceptsRequiredPolicyAwaitingInitialSnapshot() {
        ResolverRuntimeReport report = report(
                ResolverPolicyMode.REQUIRED,
                false,
                0,
                0,
                false,
                ResolverPolicySyncState.AWAITING_INITIAL_SNAPSHOT
        );

        assertFalse(report.policyReady());
        assertFalse(report.policySnapshotLoaded());
        assertEquals(0, report.policyRevision());
        assertEquals(0, report.policyRuleCount());
    }

    @Test
    void treatsLoadedRevisionZeroAsAValidSnapshot() {
        ResolverRuntimeReport report = report(
                ResolverPolicyMode.REQUIRED,
                true,
                0,
                3,
                true,
                ResolverPolicySyncState.HEALTHY
        );

        assertTrue(report.policySnapshotLoaded());
        assertEquals(0, report.policyRevision());
        assertEquals(3, report.policyRuleCount());
        assertTrue(report.policyReady());
    }

    @Test
    void acceptsHealthyDegradedAndStaleLastKnownGoodStates() {
        for (ResolverPolicySyncState state : new ResolverPolicySyncState[]{
                ResolverPolicySyncState.HEALTHY,
                ResolverPolicySyncState.DEGRADED,
                ResolverPolicySyncState.STALE
        }) {
            ResolverRuntimeReport report = report(
                    ResolverPolicyMode.REQUIRED,
                    true,
                    27,
                    6,
                    true,
                    state
            );

            assertEquals(state, report.policySyncState());
            assertTrue(report.policyReady());
        }
    }

    @Test
    void acceptsNumericUpperBounds() {
        ResolverRuntimeReport report = new ResolverRuntimeReport(
                SESSION_ID,
                BOOT_ID,
                Long.MAX_VALUE,
                Long.MAX_VALUE,
                "1.0.0",
                ResolverPolicyMode.REQUIRED,
                true,
                Long.MAX_VALUE,
                Integer.MAX_VALUE,
                true,
                ResolverPolicySyncState.HEALTHY
        );

        assertEquals(Long.MAX_VALUE, report.sessionGeneration());
        assertEquals(Long.MAX_VALUE, report.sequence());
        assertEquals(Long.MAX_VALUE, report.policyRevision());
        assertEquals(Integer.MAX_VALUE, report.policyRuleCount());
    }

    @Test
    void rejectsInvalidIdentityOrderingAndVersionFields() {
        assertThrows(
                IllegalArgumentException.class,
                () -> reportWithEnvelope(2, SESSION_ID, BOOT_ID, 4, 9)
        );
        assertThrows(
                NullPointerException.class,
                () -> reportWithEnvelope(1, null, BOOT_ID, 4, 9)
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> reportWithEnvelope(1, NIL_UUID, BOOT_ID, 4, 9)
        );
        assertThrows(
                NullPointerException.class,
                () -> reportWithEnvelope(1, SESSION_ID, null, 4, 9)
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> reportWithEnvelope(1, SESSION_ID, NIL_UUID, 4, 9)
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> reportWithEnvelope(1, SESSION_ID, BOOT_ID, 0, 9)
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> reportWithEnvelope(1, SESSION_ID, BOOT_ID, 4, 0)
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> reportWithEnvelope(1, SESSION_ID, BOOT_ID, -1, 9)
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> reportWithEnvelope(1, SESSION_ID, BOOT_ID, 4, -1)
        );
    }

    @Test
    void rejectsInvalidReportApplicationVersion() {
        assertThrows(
                NullPointerException.class,
                () -> reportWithVersion(null)
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> reportWithVersion("release candidate")
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> reportWithVersion("v" + "1".repeat(64))
        );
    }

    @Test
    void rejectsNegativePolicyNumbersAndNullEnums() {
        assertInvalidPolicyState(
                ResolverPolicyMode.REQUIRED,
                true,
                -1,
                0,
                true,
                ResolverPolicySyncState.HEALTHY
        );
        assertInvalidPolicyState(
                ResolverPolicyMode.REQUIRED,
                true,
                0,
                -1,
                true,
                ResolverPolicySyncState.HEALTHY
        );
        assertThrows(
                NullPointerException.class,
                () -> report(
                        null,
                        true,
                        0,
                        0,
                        true,
                        ResolverPolicySyncState.HEALTHY
                )
        );
        assertThrows(
                NullPointerException.class,
                () -> report(
                        ResolverPolicyMode.REQUIRED,
                        true,
                        0,
                        0,
                        true,
                        null
                )
        );
    }

    @Test
    void rejectsInconsistentDisabledState() {
        assertInvalidPolicyState(
                ResolverPolicyMode.DISABLED,
                true,
                0,
                0,
                true,
                ResolverPolicySyncState.DISABLED
        );
        assertInvalidPolicyState(
                ResolverPolicyMode.DISABLED,
                false,
                1,
                0,
                true,
                ResolverPolicySyncState.DISABLED
        );
        assertInvalidPolicyState(
                ResolverPolicyMode.DISABLED,
                false,
                0,
                1,
                true,
                ResolverPolicySyncState.DISABLED
        );
        assertInvalidPolicyState(
                ResolverPolicyMode.DISABLED,
                false,
                0,
                0,
                false,
                ResolverPolicySyncState.DISABLED
        );
        assertInvalidPolicyState(
                ResolverPolicyMode.DISABLED,
                false,
                0,
                0,
                true,
                ResolverPolicySyncState.HEALTHY
        );
    }

    @Test
    void rejectsInconsistentRequiredState() {
        assertInvalidPolicyState(
                ResolverPolicyMode.REQUIRED,
                false,
                1,
                0,
                false,
                ResolverPolicySyncState.AWAITING_INITIAL_SNAPSHOT
        );
        assertInvalidPolicyState(
                ResolverPolicyMode.REQUIRED,
                false,
                0,
                1,
                false,
                ResolverPolicySyncState.AWAITING_INITIAL_SNAPSHOT
        );
        assertInvalidPolicyState(
                ResolverPolicyMode.REQUIRED,
                false,
                0,
                0,
                true,
                ResolverPolicySyncState.AWAITING_INITIAL_SNAPSHOT
        );
        assertInvalidPolicyState(
                ResolverPolicyMode.REQUIRED,
                false,
                0,
                0,
                false,
                ResolverPolicySyncState.HEALTHY
        );
        assertInvalidPolicyState(
                ResolverPolicyMode.REQUIRED,
                true,
                0,
                0,
                false,
                ResolverPolicySyncState.HEALTHY
        );
        assertInvalidPolicyState(
                ResolverPolicyMode.REQUIRED,
                true,
                0,
                0,
                true,
                ResolverPolicySyncState.AWAITING_INITIAL_SNAPSHOT
        );
    }

    private ResolverRuntimeReport report(
            ResolverPolicyMode mode,
            boolean snapshotLoaded,
            long revision,
            int ruleCount,
            boolean ready,
            ResolverPolicySyncState syncState
    ) {
        return new ResolverRuntimeReport(
                SESSION_ID,
                BOOT_ID,
                4,
                9,
                "0.1.0-SNAPSHOT",
                mode,
                snapshotLoaded,
                revision,
                ruleCount,
                ready,
                syncState
        );
    }

    private ResolverRuntimeReport reportWithEnvelope(
            int schemaVersion,
            UUID sessionId,
            UUID bootId,
            long sessionGeneration,
            long sequence
    ) {
        return new ResolverRuntimeReport(
                schemaVersion,
                sessionId,
                bootId,
                sessionGeneration,
                sequence,
                "0.1.0-SNAPSHOT",
                ResolverPolicyMode.REQUIRED,
                true,
                0,
                0,
                true,
                ResolverPolicySyncState.HEALTHY
        );
    }

    private ResolverRuntimeReport reportWithVersion(String applicationVersion) {
        return new ResolverRuntimeReport(
                SESSION_ID,
                BOOT_ID,
                4,
                9,
                applicationVersion,
                ResolverPolicyMode.REQUIRED,
                true,
                0,
                0,
                true,
                ResolverPolicySyncState.HEALTHY
        );
    }

    private void assertInvalidPolicyState(
            ResolverPolicyMode mode,
            boolean snapshotLoaded,
            long revision,
            int ruleCount,
            boolean ready,
            ResolverPolicySyncState syncState
    ) {
        assertThrows(
                IllegalArgumentException.class,
                () -> report(
                        mode,
                        snapshotLoaded,
                        revision,
                        ruleCount,
                        ready,
                        syncState
                )
        );
    }
}
