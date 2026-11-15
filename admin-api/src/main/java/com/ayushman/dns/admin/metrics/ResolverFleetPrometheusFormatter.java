package com.ayushman.dns.admin.metrics;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.EnumMap;
import java.util.Map;

import com.ayushman.dns.admin.fleet.ResolverFleetMemberState;
import com.ayushman.dns.admin.fleet.ResolverFleetMemberStatusResponse;
import com.ayushman.dns.admin.fleet.ResolverFleetStatusResponse;
import com.ayushman.dns.admin.fleet.ResolverSessionRetentionSnapshot;
import com.ayushman.dns.fleet.ResolverFleetPolicyState;

/** Formats the bounded resolver-fleet snapshot for Prometheus. */
final class ResolverFleetPrometheusFormatter {

    private static final String[] POLICY_STATE_LABELS = {
            "unobserved",
            "not_converged",
            "converged"
    };

    private ResolverFleetPrometheusFormatter() {
    }

    static String format(
            ResolverFleetStatusResponse status,
            ResolverSessionRetentionSnapshot retention
    ) {
        StringBuilder output = new StringBuilder(2_048);

        helpAndType(
                output,
                "dns_admin_fleet_policy_state",
                "Current resolver fleet policy state as a one-hot gauge."
        );
        String activePolicyState = policyStateLabel(status.policyEnforcement());
        for (String state : POLICY_STATE_LABELS) {
            sample(
                    output,
                    "dns_admin_fleet_policy_state{state=\"" + state + "\"}",
                    state.equals(activePolicyState) ? 1 : 0
            );
        }

        helpAndType(
                output,
                "dns_admin_fleet_resolvers",
                "Resolver count by fleet membership and convergence scope."
        );
        sample(
                output,
                "dns_admin_fleet_resolvers{scope=\"registered\"}",
                status.registeredResolverCount()
        );
        sample(
                output,
                "dns_admin_fleet_resolvers{scope=\"expected\"}",
                status.expectedResolverCount()
        );
        sample(
                output,
                "dns_admin_fleet_resolvers{scope=\"fresh\"}",
                status.freshResolverCount()
        );
        sample(
                output,
                "dns_admin_fleet_resolvers{scope=\"converged\"}",
                status.convergedResolverCount()
        );

        helpAndType(
                output,
                "dns_admin_fleet_member_state",
                "Resolver count by bounded fleet diagnostic state."
        );
        Map<ResolverFleetMemberState, Long> memberStateCounts = memberStateCounts(
                status
        );
        for (ResolverFleetMemberState state : ResolverFleetMemberState.values()) {
            sample(
                    output,
                    "dns_admin_fleet_member_state{state=\""
                            + memberStateLabel(state)
                            + "\"}",
                    memberStateCounts.get(state)
            );
        }

        helpAndType(
                output,
                "dns_admin_policy_publication_revision",
                "Current published DNS policy revision."
        );
        sample(
                output,
                "dns_admin_policy_publication_revision",
                status.publishedPolicyRevision()
        );

        helpAndType(
                output,
                "dns_admin_policy_rules",
                "DNS policy rule count by persistence and publication scope."
        );
        sample(
                output,
                "dns_admin_policy_rules{scope=\"persisted\"}",
                status.persistedPolicyRuleCount()
        );
        sample(
                output,
                "dns_admin_policy_rules{scope=\"enabled\"}",
                status.publishedPolicyRuleCount()
        );

        helpAndType(
                output,
                "dns_admin_fleet_report_freshness_threshold_seconds",
                "Maximum accepted resolver report age in seconds."
        );
        sample(
                output,
                "dns_admin_fleet_report_freshness_threshold_seconds",
                decimalSeconds(status.reportFreshnessMillis())
        );

        helpAndType(
                output,
                "dns_admin_fleet_evaluated_timestamp_seconds",
                "Unix timestamp of the fleet snapshot evaluation."
        );
        sample(
                output,
                "dns_admin_fleet_evaluated_timestamp_seconds",
                decimalSeconds(status.evaluatedAt())
        );

        helpAndType(
                output,
                "dns_admin_fleet_sessions",
                "Detailed resolver session count by bounded lifecycle state."
        );
        sample(
                output,
                "dns_admin_fleet_sessions{state=\"active\"}",
                retention.activeSessions()
        );
        sample(
                output,
                "dns_admin_fleet_sessions{state=\"superseded\"}",
                retention.supersededSessions()
        );
        sample(
                output,
                "dns_admin_fleet_sessions{state=\"retention_eligible\"}",
                retention.retentionEligibleSessions()
        );

        helpAndType(
                output,
                "dns_admin_fleet_boot_fence_entries",
                "Permanent resolver boot replay-fence entries."
        );
        sample(
                output,
                "dns_admin_fleet_boot_fence_entries",
                retention.bootFenceEntries()
        );

        helpAndType(
                output,
                "dns_admin_fleet_session_retention_seconds",
                "Configured detailed resolver session retention in seconds."
        );
        sample(
                output,
                "dns_admin_fleet_session_retention_seconds",
                decimalSeconds(retention.retentionMillis())
        );

        helpAndCounterType(
                output,
                "dns_admin_fleet_session_cleanup_runs_total",
                "Resolver session cleanup runs by outcome."
        );
        sample(
                output,
                "dns_admin_fleet_session_cleanup_runs_total{result=\"success\"}",
                retention.successfulCleanupRuns()
        );
        sample(
                output,
                "dns_admin_fleet_session_cleanup_runs_total{result=\"failure\"}",
                retention.failedCleanupRuns()
        );

        helpAndCounterType(
                output,
                "dns_admin_fleet_session_cleanup_deleted_total",
                "Detailed superseded resolver sessions deleted by cleanup."
        );
        sample(
                output,
                "dns_admin_fleet_session_cleanup_deleted_total",
                retention.deletedSessions()
        );

        helpAndType(
                output,
                "dns_admin_fleet_session_cleanup_last_success_timestamp_seconds",
                "Unix timestamp of the last successful session cleanup run."
        );
        sample(
                output,
                "dns_admin_fleet_session_cleanup_last_success_timestamp_seconds",
                decimalSecondsFromEpochMillis(
                        retention.lastSuccessfulCleanupEpochMillis()
                )
        );

        helpAndType(
                output,
                "dns_admin_fleet_session_cleanup_consecutive_failures",
                "Consecutive failed resolver session cleanup runs."
        );
        sample(
                output,
                "dns_admin_fleet_session_cleanup_consecutive_failures",
                retention.consecutiveCleanupFailures()
        );

        helpAndType(
                output,
                "dns_admin_fleet_session_cleanup_saturated",
                "Whether eligible session history remains after the bounded cleanup run."
        );
        sample(
                output,
                "dns_admin_fleet_session_cleanup_saturated",
                retention.cleanupSaturated() ? 1 : 0
        );

        return output.toString();
    }

    private static Map<ResolverFleetMemberState, Long> memberStateCounts(
            ResolverFleetStatusResponse status
    ) {
        Map<ResolverFleetMemberState, Long> counts = new EnumMap<>(
                ResolverFleetMemberState.class
        );
        for (ResolverFleetMemberState state : ResolverFleetMemberState.values()) {
            counts.put(state, 0L);
        }
        for (ResolverFleetMemberStatusResponse member : status.resolvers()) {
            counts.compute(member.state(), (state, count) -> count + 1);
        }
        return counts;
    }

    private static String policyStateLabel(ResolverFleetPolicyState state) {
        return switch (state) {
            case DATA_PLANE_UNOBSERVED -> "unobserved";
            case DATA_PLANE_NOT_CONVERGED -> "not_converged";
            case DATA_PLANE_CONVERGED -> "converged";
        };
    }

    private static String memberStateLabel(ResolverFleetMemberState state) {
        return state.name().toLowerCase(java.util.Locale.ROOT);
    }

    private static String decimalSeconds(long milliseconds) {
        return BigDecimal.valueOf(milliseconds, 3)
                .stripTrailingZeros()
                .toPlainString();
    }

    private static String decimalSecondsFromEpochMillis(long milliseconds) {
        if (milliseconds == 0) {
            return "0";
        }
        return decimalSeconds(milliseconds);
    }

    private static String decimalSeconds(Instant instant) {
        return BigDecimal.valueOf(instant.getEpochSecond())
                .add(BigDecimal.valueOf(instant.getNano(), 9))
                .stripTrailingZeros()
                .toPlainString();
    }

    private static void helpAndType(
            StringBuilder output,
            String name,
            String help
    ) {
        output.append("# HELP ").append(name).append(' ').append(help).append('\n');
        output.append("# TYPE ").append(name).append(" gauge\n");
    }

    private static void helpAndCounterType(
            StringBuilder output,
            String name,
            String help
    ) {
        output.append("# HELP ").append(name).append(' ').append(help).append('\n');
        output.append("# TYPE ").append(name).append(" counter\n");
    }

    private static void sample(StringBuilder output, String name, long value) {
        sample(output, name, Long.toString(value));
    }

    private static void sample(StringBuilder output, String name, String value) {
        output.append(name).append(' ').append(value).append('\n');
    }
}
