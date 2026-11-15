package com.ayushman.dns.admin.metrics;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;

import com.ayushman.dns.admin.fleet.ResolverFleetMemberState;
import com.ayushman.dns.admin.fleet.ResolverFleetMemberStatusResponse;
import com.ayushman.dns.admin.fleet.ResolverFleetStatusResponse;
import com.ayushman.dns.admin.fleet.ResolverSessionRetentionSnapshot;
import com.ayushman.dns.fleet.ResolverFleetPolicyState;
import org.junit.jupiter.api.Test;

class ResolverFleetPrometheusFormatterTest {

    @Test
    void rendersDeterministicFixedCardinalityPrometheusText() {
        ResolverFleetStatusResponse status = new ResolverFleetStatusResponse(
                1,
                Instant.parse("2026-11-14T12:34:56.123456Z"),
                120_500,
                42,
                9,
                7,
                ResolverFleetPolicyState.DATA_PLANE_NOT_CONVERGED,
                5,
                4,
                3,
                2,
                List.of(
                        member("private-resolver-a", ResolverFleetMemberState.NO_REPORT),
                        member("private-resolver-b", ResolverFleetMemberState.CONVERGED),
                        member("private-resolver-c", ResolverFleetMemberState.CONVERGED)
                )
        );

        ResolverSessionRetentionSnapshot retention =
                new ResolverSessionRetentionSnapshot(
                        2,
                        8,
                        3,
                        10,
                        2_592_000_000L,
                        12,
                        2,
                        44,
                        1_794_659_696_500L,
                        0,
                        true
                );

        String output = ResolverFleetPrometheusFormatter.format(
                status,
                retention
        );

        assertThat(output).isEqualTo("""
                # HELP dns_admin_fleet_policy_state Current resolver fleet policy state as a one-hot gauge.
                # TYPE dns_admin_fleet_policy_state gauge
                dns_admin_fleet_policy_state{state="unobserved"} 0
                dns_admin_fleet_policy_state{state="not_converged"} 1
                dns_admin_fleet_policy_state{state="converged"} 0
                # HELP dns_admin_fleet_resolvers Resolver count by fleet membership and convergence scope.
                # TYPE dns_admin_fleet_resolvers gauge
                dns_admin_fleet_resolvers{scope="registered"} 5
                dns_admin_fleet_resolvers{scope="expected"} 4
                dns_admin_fleet_resolvers{scope="fresh"} 3
                dns_admin_fleet_resolvers{scope="converged"} 2
                # HELP dns_admin_fleet_member_state Resolver count by bounded fleet diagnostic state.
                # TYPE dns_admin_fleet_member_state gauge
                dns_admin_fleet_member_state{state="excluded_disabled"} 0
                dns_admin_fleet_member_state{state="no_active_session"} 0
                dns_admin_fleet_member_state{state="no_report"} 1
                dns_admin_fleet_member_state{state="report_stale"} 0
                dns_admin_fleet_member_state{state="policy_mode_disabled"} 0
                dns_admin_fleet_member_state{state="policy_not_ready"} 0
                dns_admin_fleet_member_state{state="revision_mismatch"} 0
                dns_admin_fleet_member_state{state="rule_count_mismatch"} 0
                dns_admin_fleet_member_state{state="converged"} 2
                # HELP dns_admin_policy_publication_revision Current published DNS policy revision.
                # TYPE dns_admin_policy_publication_revision gauge
                dns_admin_policy_publication_revision 42
                # HELP dns_admin_policy_rules DNS policy rule count by persistence and publication scope.
                # TYPE dns_admin_policy_rules gauge
                dns_admin_policy_rules{scope="persisted"} 9
                dns_admin_policy_rules{scope="enabled"} 7
                # HELP dns_admin_fleet_report_freshness_threshold_seconds Maximum accepted resolver report age in seconds.
                # TYPE dns_admin_fleet_report_freshness_threshold_seconds gauge
                dns_admin_fleet_report_freshness_threshold_seconds 120.5
                # HELP dns_admin_fleet_evaluated_timestamp_seconds Unix timestamp of the fleet snapshot evaluation.
                # TYPE dns_admin_fleet_evaluated_timestamp_seconds gauge
                dns_admin_fleet_evaluated_timestamp_seconds 1794659696.123456
                # HELP dns_admin_fleet_sessions Detailed resolver session count by bounded lifecycle state.
                # TYPE dns_admin_fleet_sessions gauge
                dns_admin_fleet_sessions{state="active"} 2
                dns_admin_fleet_sessions{state="superseded"} 8
                dns_admin_fleet_sessions{state="retention_eligible"} 3
                # HELP dns_admin_fleet_boot_fence_entries Permanent resolver boot replay-fence entries.
                # TYPE dns_admin_fleet_boot_fence_entries gauge
                dns_admin_fleet_boot_fence_entries 10
                # HELP dns_admin_fleet_session_retention_seconds Configured detailed resolver session retention in seconds.
                # TYPE dns_admin_fleet_session_retention_seconds gauge
                dns_admin_fleet_session_retention_seconds 2592000
                # HELP dns_admin_fleet_session_cleanup_runs_total Resolver session cleanup runs by outcome.
                # TYPE dns_admin_fleet_session_cleanup_runs_total counter
                dns_admin_fleet_session_cleanup_runs_total{result="success"} 12
                dns_admin_fleet_session_cleanup_runs_total{result="failure"} 2
                # HELP dns_admin_fleet_session_cleanup_deleted_total Detailed superseded resolver sessions deleted by cleanup.
                # TYPE dns_admin_fleet_session_cleanup_deleted_total counter
                dns_admin_fleet_session_cleanup_deleted_total 44
                # HELP dns_admin_fleet_session_cleanup_last_success_timestamp_seconds Unix timestamp of the last successful session cleanup run.
                # TYPE dns_admin_fleet_session_cleanup_last_success_timestamp_seconds gauge
                dns_admin_fleet_session_cleanup_last_success_timestamp_seconds 1794659696.5
                # HELP dns_admin_fleet_session_cleanup_consecutive_failures Consecutive failed resolver session cleanup runs.
                # TYPE dns_admin_fleet_session_cleanup_consecutive_failures gauge
                dns_admin_fleet_session_cleanup_consecutive_failures 0
                # HELP dns_admin_fleet_session_cleanup_saturated Whether eligible session history remains after the bounded cleanup run.
                # TYPE dns_admin_fleet_session_cleanup_saturated gauge
                dns_admin_fleet_session_cleanup_saturated 1
                """);
        assertThat(output)
                .doesNotContain("private-resolver")
                .doesNotContain("applicationVersion")
                .endsWith("\n");
    }

    private ResolverFleetMemberStatusResponse member(
            String resolverId,
            ResolverFleetMemberState state
    ) {
        return new ResolverFleetMemberStatusResponse(
                resolverId,
                state != ResolverFleetMemberState.EXCLUDED_DISABLED,
                state,
                null,
                "private-build-version",
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null
        );
    }
}
