package com.ayushman.dns.admin.fleet;

import java.time.Instant;

import com.ayushman.dns.fleet.ResolverPolicyMode;
import com.ayushman.dns.fleet.ResolverPolicySyncState;

/** Non-secret status for one registered resolver. */
public record ResolverFleetMemberStatusResponse(
        String resolverId,
        boolean expected,
        ResolverFleetMemberState state,
        Long sessionGeneration,
        String applicationVersion,
        Instant lastReportReceivedAt,
        Long reportAgeMillis,
        Boolean reportFresh,
        ResolverPolicyMode policyMode,
        Boolean policySnapshotLoaded,
        Long policyRevision,
        Integer policyRuleCount,
        Boolean policyReady,
        ResolverPolicySyncState policySyncState
) {
}
