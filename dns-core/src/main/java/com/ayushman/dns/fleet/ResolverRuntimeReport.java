package com.ayushman.dns.fleet;

import java.util.Objects;
import java.util.UUID;

/**
 * Versioned, privacy-safe policy runtime report for one resolver session.
 *
 * <p>The report deliberately contains no client timestamp, policy domains,
 * endpoint details, or error text. Receipt time and resolver identity belong
 * to the authenticated control-plane session.</p>
 */
public record ResolverRuntimeReport(
        int schemaVersion,
        UUID sessionId,
        UUID bootId,
        long sessionGeneration,
        long sequence,
        String applicationVersion,
        ResolverPolicyMode policyMode,
        boolean policySnapshotLoaded,
        long policyRevision,
        int policyRuleCount,
        boolean policyReady,
        ResolverPolicySyncState policySyncState
) {

    public static final int CURRENT_SCHEMA_VERSION =
            ResolverRuntimeContracts.CURRENT_SCHEMA_VERSION;

    public ResolverRuntimeReport {
        ResolverRuntimeContracts.requireCurrentSchema(schemaVersion);
        sessionId = ResolverRuntimeContracts.requireNonNilUuid(
                sessionId,
                "sessionId"
        );
        bootId = ResolverRuntimeContracts.requireNonNilUuid(bootId, "bootId");
        if (sessionGeneration < 1) {
            throw new IllegalArgumentException(
                    "resolver session generation must be positive"
            );
        }
        if (sequence < 1) {
            throw new IllegalArgumentException(
                    "resolver report sequence must be positive"
            );
        }
        applicationVersion = ResolverRuntimeContracts.requireApplicationVersion(
                applicationVersion
        );
        policyMode = Objects.requireNonNull(
                policyMode,
                "policyMode must not be null"
        );
        policySyncState = Objects.requireNonNull(
                policySyncState,
                "policySyncState must not be null"
        );
        if (policyRevision < 0) {
            throw new IllegalArgumentException(
                    "active policy revision must not be negative"
            );
        }
        if (policyRuleCount < 0) {
            throw new IllegalArgumentException(
                    "active policy rule count must not be negative"
            );
        }

        validatePolicyState(
                policyMode,
                policySnapshotLoaded,
                policyRevision,
                policyRuleCount,
                policyReady,
                policySyncState
        );
    }

    public ResolverRuntimeReport(
            UUID sessionId,
            UUID bootId,
            long sessionGeneration,
            long sequence,
            String applicationVersion,
            ResolverPolicyMode policyMode,
            boolean policySnapshotLoaded,
            long policyRevision,
            int policyRuleCount,
            boolean policyReady,
            ResolverPolicySyncState policySyncState
    ) {
        this(
                CURRENT_SCHEMA_VERSION,
                sessionId,
                bootId,
                sessionGeneration,
                sequence,
                applicationVersion,
                policyMode,
                policySnapshotLoaded,
                policyRevision,
                policyRuleCount,
                policyReady,
                policySyncState
        );
    }

    private static void validatePolicyState(
            ResolverPolicyMode mode,
            boolean snapshotLoaded,
            long revision,
            int ruleCount,
            boolean ready,
            ResolverPolicySyncState syncState
    ) {
        boolean valid = switch (mode) {
            case DISABLED -> !snapshotLoaded
                    && revision == 0
                    && ruleCount == 0
                    && ready
                    && syncState == ResolverPolicySyncState.DISABLED;
            case REQUIRED -> validRequiredState(
                    snapshotLoaded,
                    revision,
                    ruleCount,
                    ready,
                    syncState
            );
        };
        if (!valid) {
            throw new IllegalArgumentException(
                    "policy runtime fields do not form a valid state"
            );
        }
    }

    private static boolean validRequiredState(
            boolean snapshotLoaded,
            long revision,
            int ruleCount,
            boolean ready,
            ResolverPolicySyncState syncState
    ) {
        if (!snapshotLoaded) {
            return revision == 0
                    && ruleCount == 0
                    && !ready
                    && syncState
                    == ResolverPolicySyncState.AWAITING_INITIAL_SNAPSHOT;
        }

        boolean activeSyncState = switch (syncState) {
            case HEALTHY, DEGRADED, STALE -> true;
            case DISABLED, AWAITING_INITIAL_SNAPSHOT -> false;
        };
        return ready && activeSyncState;
    }
}
