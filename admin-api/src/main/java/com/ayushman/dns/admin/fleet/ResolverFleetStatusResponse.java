package com.ayushman.dns.admin.fleet;

import java.time.Instant;
import java.util.List;

import com.ayushman.dns.fleet.ResolverFleetPolicyState;

/** Freshness-aware aggregate view of the registered resolver fleet. */
public record ResolverFleetStatusResponse(
        int schemaVersion,
        Instant evaluatedAt,
        long reportFreshnessMillis,
        long publishedPolicyRevision,
        long persistedPolicyRuleCount,
        long publishedPolicyRuleCount,
        ResolverFleetPolicyState policyEnforcement,
        long registeredResolverCount,
        long expectedResolverCount,
        long freshResolverCount,
        long convergedResolverCount,
        List<ResolverFleetMemberStatusResponse> resolvers
) {

    public static final int CURRENT_SCHEMA_VERSION = 1;

    public ResolverFleetStatusResponse {
        resolvers = List.copyOf(resolvers);
    }
}
