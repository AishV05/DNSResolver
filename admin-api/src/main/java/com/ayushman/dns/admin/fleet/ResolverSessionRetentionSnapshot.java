package com.ayushman.dns.admin.fleet;

/** Fixed-cardinality view used by the authenticated fleet metrics endpoint. */
public record ResolverSessionRetentionSnapshot(
        long activeSessions,
        long supersededSessions,
        long retentionEligibleSessions,
        long bootFenceEntries,
        long retentionMillis,
        long successfulCleanupRuns,
        long failedCleanupRuns,
        long deletedSessions,
        long lastSuccessfulCleanupEpochMillis,
        int consecutiveCleanupFailures,
        boolean cleanupSaturated
) {
}

