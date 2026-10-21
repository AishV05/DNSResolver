package com.ayushman.dns.server;

import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.TimeUnit;

import com.ayushman.dns.policy.DnsPolicySnapshot;
import org.junit.jupiter.api.Test;

class PrometheusMetricsFormatterTest {

    @Test
    void rendersFixedCardinalityPrometheusMetrics() {

        ServerMetrics metrics = new ServerMetrics();
        metrics.recordReceivedRequest();
        metrics.recordAdmittedRequest();
        metrics.recordOversizedDrop();
        metrics.recordRateLimitedDrop();
        metrics.recordQueueFullDrop();
        metrics.recordMalformedRequest();
        metrics.recordUnsupportedEdnsVersion();
        metrics.recordResolvedRequest(TimeUnit.MILLISECONDS.toNanos(12));
        metrics.recordResolverFailure();
        metrics.recordReceivedRequest(DnsTransport.TCP);
        metrics.recordAdmittedRequest(DnsTransport.TCP);
        metrics.recordResolvedRequest(
                DnsTransport.TCP,
                TimeUnit.MILLISECONDS.toNanos(3)
        );
        metrics.recordTcpConnectionAccepted();
        metrics.recordTcpConnectionLimitRejection();
        metrics.recordTcpConnectionQueueRejection();
        metrics.recordTcpConnectionTimeout();
        metrics.recordTcpProtocolError();
        PolicySnapshotStore policyStore = new PolicySnapshotStore(
                PolicySyncMode.REQUIRED
        );
        policyStore.activate(new DnsPolicySnapshot(
                7,
                Instant.parse("2026-10-05T00:00:00Z"),
                List.of()
        ));
        PolicyTelemetry policyTelemetry = new PolicyTelemetry(
                PolicySyncMode.REQUIRED,
                60_000,
                Clock.fixed(
                        Instant.parse("2026-10-05T00:00:30Z"),
                        ZoneOffset.UTC
                )
        );
        policyTelemetry.recordSyncAttempt();
        policyTelemetry.recordSyncActivated();
        policyTelemetry.recordBlocked(DnsTransport.UDP);
        policyTelemetry.recordUnavailable(DnsTransport.TCP);

        String output = PrometheusMetricsFormatter.format(
                true,
                true,
                true,
                metrics.snapshot(),
                policyTelemetry.snapshot(policyStore.snapshotStatus())
        );

        assertTrue(output.contains("# TYPE dns_server_running gauge\n"));
        assertTrue(output.contains("dns_server_running 1\n"));
        assertTrue(output.contains("dns_requests_received_total 2\n"));
        assertTrue(output.contains("dns_requests_admitted_total 2\n"));
        assertTrue(output.contains(
                "dns_transport_listener_running{transport=\"udp\"} 1\n"
        ));
        assertTrue(output.contains(
                "dns_transport_listener_running{transport=\"tcp\"} 1\n"
        ));
        assertTrue(output.contains(
                "dns_transport_requests_received_total{transport=\"udp\"} 1\n"
        ));
        assertTrue(output.contains(
                "dns_transport_requests_received_total{transport=\"tcp\"} 1\n"
        ));
        assertTrue(output.contains(
                "dns_request_drops_total{reason=\"oversized\"} 1\n"
        ));
        assertTrue(output.contains(
                "dns_request_drops_total{reason=\"rate_limited\"} 1\n"
        ));
        assertTrue(output.contains(
                "dns_request_drops_total{reason=\"queue_full\"} 1\n"
        ));
        assertTrue(output.contains("dns_malformed_requests_total 1\n"));
        assertTrue(output.contains("dns_edns_unsupported_version_total 1\n"));
        assertTrue(output.contains("dns_resolved_requests_total 2\n"));
        assertTrue(output.contains("dns_resolver_failures_total 1\n"));
        assertTrue(output.contains(
                "dns_successful_query_handling_seconds_sum 0.015\n"
        ));
        assertTrue(output.contains(
                "dns_successful_query_handling_seconds_count 2\n"
        ));
        assertTrue(output.contains("dns_tcp_connections_active 1\n"));
        assertTrue(output.contains(
                "dns_tcp_connection_rejections_total{reason=\"connection_limit\"} 1\n"
        ));
        assertTrue(output.contains(
                "dns_tcp_connection_rejections_total{reason=\"worker_queue_full\"} 1\n"
        ));
        assertTrue(output.contains(
                "dns_tcp_connection_timeouts_total 1\n"
        ));
        assertTrue(output.contains("dns_tcp_protocol_errors_total 1\n"));
        assertTrue(output.contains(
                "dns_policy_mode{mode=\"required\"} 1\n"
        ));
        assertTrue(output.contains("dns_policy_ready 1\n"));
        assertTrue(output.contains("dns_policy_snapshot_loaded 1\n"));
        assertTrue(output.contains("dns_policy_snapshot_revision 7\n"));
        assertTrue(output.contains("dns_policy_snapshot_rules 0\n"));
        assertTrue(output.contains(
                "dns_policy_snapshot_published_age_seconds 30\n"
        ));
        assertTrue(output.contains(
                "dns_policy_sync_results_total{result=\"activated\"} 1\n"
        ));
        assertTrue(output.contains(
                "dns_policy_sync_results_total{result=\"failure\"} 0\n"
        ));
        assertTrue(output.contains(
                "dns_policy_blocked_requests_total{transport=\"udp\"} 1\n"
        ));
        assertTrue(output.contains(
                "dns_policy_unavailable_requests_total{transport=\"tcp\"} 1\n"
        ));
        assertTrue(output.contains("dns_policy_sync_stale 0\n"));
        assertTrue(output.endsWith("\n"));
    }
}
