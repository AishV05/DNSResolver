package com.ayushman.dns.server;

/**
 * Renders the DNS server's fixed-cardinality metrics using the Prometheus
 * text exposition format.
 */
final class PrometheusMetricsFormatter {

    static final String CONTENT_TYPE =
            "text/plain; version=0.0.4; charset=utf-8";

    private PrometheusMetricsFormatter() {
    }

    static String format(
            boolean serverRunning,
            ServerMetrics.Snapshot snapshot
    ) {
        return format(
                serverRunning,
                serverRunning,
                serverRunning,
                snapshot,
                PolicyTelemetry.Snapshot.disabled()
        );
    }

    static String format(
            boolean serverRunning,
            boolean udpRunning,
            boolean tcpRunning,
            ServerMetrics.Snapshot snapshot
    ) {
        return format(
                serverRunning,
                udpRunning,
                tcpRunning,
                snapshot,
                PolicyTelemetry.Snapshot.disabled()
        );
    }

    static String format(
            boolean serverRunning,
            boolean udpRunning,
            boolean tcpRunning,
            ServerMetrics.Snapshot snapshot,
            PolicyTelemetry.Snapshot policy
    ) {

        if (snapshot == null || policy == null) {
            throw new IllegalArgumentException("snapshot must not be null");
        }

        StringBuilder output = new StringBuilder();

        appendGauge(
                output,
                "dns_server_running",
                "Whether DNS is ready, including transports and required policy.",
                serverRunning ? 1 : 0
        );
        appendTransportListenerGauges(output, udpRunning, tcpRunning);
        appendCounter(
                output,
                "dns_requests_received_total",
                "Total DNS requests received by all transport listeners.",
                snapshot.receivedRequests()
        );
        appendCounter(
                output,
                "dns_requests_admitted_total",
                "Total DNS requests admitted by all transports.",
                snapshot.admittedRequests()
        );
        appendDrops(output, snapshot);
        appendCounter(
                output,
                "dns_malformed_requests_total",
                "Total DNS requests rejected because packet parsing failed.",
                snapshot.malformedRequests()
        );
        appendCounter(
                output,
                "dns_edns_unsupported_version_total",
                "Total DNS requests rejected because EDNS version is unsupported.",
                snapshot.unsupportedEdnsVersions()
        );
        appendCounter(
                output,
                "dns_resolved_requests_total",
                "Total DNS requests resolved successfully.",
                snapshot.resolvedRequests()
        );
        appendCounter(
                output,
                "dns_resolver_failures_total",
                "Total DNS requests that ended in a resolver failure.",
                snapshot.resolverFailures()
        );
        appendSuccessfulHandlingDuration(output, snapshot);
        appendTransportRequests(output, snapshot);
        appendTcpConnections(output, snapshot);
        appendPolicyMetrics(output, policy);

        return output.toString();
    }

    private static void appendPolicyMetrics(
            StringBuilder output,
            PolicyTelemetry.Snapshot policy
    ) {
        output.append("# HELP dns_policy_mode Configured DNS policy mode.\n")
                .append("# TYPE dns_policy_mode gauge\n");
        appendLabeledValue(
                output,
                "dns_policy_mode",
                "mode",
                "disabled",
                policy.mode() == PolicySyncMode.DISABLED ? 1 : 0
        );
        appendLabeledValue(
                output,
                "dns_policy_mode",
                "mode",
                "required",
                policy.mode() == PolicySyncMode.REQUIRED ? 1 : 0
        );
        appendGauge(
                output,
                "dns_policy_ready",
                "Whether policy state permits DNS queries to be answered.",
                policy.ready() ? 1 : 0
        );
        appendGauge(
                output,
                "dns_policy_snapshot_loaded",
                "Whether a complete policy snapshot is active.",
                policy.snapshotLoaded() ? 1 : 0
        );
        appendGauge(
                output,
                "dns_policy_snapshot_revision",
                "Active policy snapshot revision; pair with loaded state.",
                policy.revision()
        );
        appendGauge(
                output,
                "dns_policy_snapshot_rules",
                "Number of rules in the active policy snapshot.",
                policy.ruleCount()
        );
        appendGauge(
                output,
                "dns_policy_snapshot_published_timestamp_seconds",
                "Source publication time of the active snapshot.",
                policy.publishedTimestampSeconds()
        );
        appendGauge(
                output,
                "dns_policy_snapshot_published_age_seconds",
                "Age of the source publication time; not sync freshness.",
                policy.publishedAgeSeconds()
        );
        appendCounter(
                output,
                "dns_policy_sync_attempts_total",
                "Total policy synchronization attempts.",
                policy.syncAttempts()
        );
        output.append("# HELP dns_policy_sync_results_total ")
                .append("Policy synchronization outcomes.\n")
                .append("# TYPE dns_policy_sync_results_total counter\n");
        appendLabeledValue(
                output,
                "dns_policy_sync_results_total",
                "result",
                "activated",
                policy.syncActivated()
        );
        appendLabeledValue(
                output,
                "dns_policy_sync_results_total",
                "result",
                "unchanged",
                policy.syncUnchanged()
        );
        appendLabeledValue(
                output,
                "dns_policy_sync_results_total",
                "result",
                "not_modified",
                policy.syncNotModified()
        );
        appendLabeledValue(
                output,
                "dns_policy_sync_results_total",
                "result",
                "failure",
                policy.syncFailures()
        );
        appendGauge(
                output,
                "dns_policy_sync_last_attempt_timestamp_seconds",
                "Unix time of the latest policy synchronization attempt.",
                policy.lastAttemptTimestampSeconds()
        );
        appendGauge(
                output,
                "dns_policy_sync_last_success_timestamp_seconds",
                "Unix time of the latest valid policy synchronization response.",
                policy.lastSuccessTimestampSeconds()
        );
        appendGauge(
                output,
                "dns_policy_sync_last_success_age_seconds",
                "Seconds since the latest valid synchronization response.",
                policy.lastSuccessAgeSeconds()
        );
        appendGauge(
                output,
                "dns_policy_sync_consecutive_failures",
                "Consecutive policy synchronization failures.",
                policy.consecutiveFailures()
        );
        appendGauge(
                output,
                "dns_policy_sync_stale",
                "Whether last-known-good policy synchronization is stale.",
                policy.stale() ? 1 : 0
        );
        appendGauge(
                output,
                "dns_policy_sync_stale_after_seconds",
                "Configured threshold for policy synchronization staleness.",
                policy.staleAfterSeconds()
        );
        appendTransportCounter(
                output,
                "dns_policy_blocked_requests_total",
                "DNS requests blocked by active policy by transport.",
                policy.udpBlockedRequests(),
                policy.tcpBlockedRequests()
        );
        appendTransportCounter(
                output,
                "dns_policy_unavailable_requests_total",
                "DNS requests failed closed because policy was unavailable.",
                policy.udpUnavailableRequests(),
                policy.tcpUnavailableRequests()
        );
    }

    private static void appendTransportListenerGauges(
            StringBuilder output,
            boolean udpRunning,
            boolean tcpRunning
    ) {
        output.append("# HELP dns_transport_listener_running ")
                .append("Whether a DNS transport listener is running.\n")
                .append("# TYPE dns_transport_listener_running gauge\n");
        appendLabeledValue(
                output,
                "dns_transport_listener_running",
                "transport",
                "udp",
                udpRunning ? 1 : 0
        );
        appendLabeledValue(
                output,
                "dns_transport_listener_running",
                "transport",
                "tcp",
                tcpRunning ? 1 : 0
        );
    }

    private static void appendTransportRequests(
            StringBuilder output,
            ServerMetrics.Snapshot snapshot
    ) {
        appendTransportCounter(
                output,
                "dns_transport_requests_received_total",
                "DNS requests received by transport.",
                snapshot.udpReceivedRequests(),
                snapshot.tcpReceivedRequests()
        );
        appendTransportCounter(
                output,
                "dns_transport_requests_admitted_total",
                "DNS requests admitted by transport.",
                snapshot.udpAdmittedRequests(),
                snapshot.tcpAdmittedRequests()
        );
        appendTransportCounter(
                output,
                "dns_transport_resolved_requests_total",
                "DNS requests resolved successfully by transport.",
                snapshot.udpResolvedRequests(),
                snapshot.tcpResolvedRequests()
        );
        appendTransportCounter(
                output,
                "dns_transport_resolver_failures_total",
                "DNS resolver failures by client transport.",
                snapshot.udpResolverFailures(),
                snapshot.tcpResolverFailures()
        );
    }

    private static void appendTransportCounter(
            StringBuilder output,
            String name,
            String help,
            long udpValue,
            long tcpValue
    ) {
        output.append("# HELP ").append(name).append(' ')
                .append(help).append('\n')
                .append("# TYPE ").append(name).append(" counter\n");
        appendLabeledValue(output, name, "transport", "udp", udpValue);
        appendLabeledValue(output, name, "transport", "tcp", tcpValue);
    }

    private static void appendTcpConnections(
            StringBuilder output,
            ServerMetrics.Snapshot snapshot
    ) {
        appendCounter(
                output,
                "dns_tcp_connections_accepted_total",
                "Total TCP connections admitted by the DNS listener.",
                snapshot.tcpConnectionsAccepted()
        );
        appendGauge(
                output,
                "dns_tcp_connections_active",
                "Current admitted TCP DNS connections.",
                snapshot.tcpConnectionsActive()
        );
        output.append("# HELP dns_tcp_connection_rejections_total ")
                .append("TCP DNS connections rejected before processing.\n")
                .append("# TYPE dns_tcp_connection_rejections_total counter\n");
        appendLabeledValue(
                output,
                "dns_tcp_connection_rejections_total",
                "reason",
                "connection_limit",
                snapshot.tcpConnectionLimitRejections()
        );
        appendLabeledValue(
                output,
                "dns_tcp_connection_rejections_total",
                "reason",
                "worker_queue_full",
                snapshot.tcpConnectionQueueRejections()
        );
        appendCounter(
                output,
                "dns_tcp_connection_timeouts_total",
                "TCP DNS connections closed after an I/O deadline.",
                snapshot.tcpConnectionTimeouts()
        );
        appendCounter(
                output,
                "dns_tcp_protocol_errors_total",
                "TCP DNS connections closed for invalid or incomplete framing.",
                snapshot.tcpProtocolErrors()
        );
    }

    private static void appendDrops(
            StringBuilder output,
            ServerMetrics.Snapshot snapshot
    ) {

        output.append("# HELP dns_request_drops_total ")
                .append("Total DNS requests dropped before resolution.\n")
                .append("# TYPE dns_request_drops_total counter\n");
        appendLabeledCounter(
                output,
                "dns_request_drops_total",
                "oversized",
                snapshot.oversizedDrops()
        );
        appendLabeledCounter(
                output,
                "dns_request_drops_total",
                "rate_limited",
                snapshot.rateLimitedDrops()
        );
        appendLabeledCounter(
                output,
                "dns_request_drops_total",
                "queue_full",
                snapshot.queueFullDrops()
        );
    }

    private static void appendSuccessfulHandlingDuration(
            StringBuilder output,
            ServerMetrics.Snapshot snapshot
    ) {

        output.append("# HELP dns_successful_query_handling_seconds ")
                .append("Time spent handling successfully resolved DNS queries.\n")
                .append("# TYPE dns_successful_query_handling_seconds summary\n")
                .append("dns_successful_query_handling_seconds_sum ")
                .append(snapshot.totalSuccessfulHandlingNanos()
                        / 1_000_000_000.0)
                .append('\n')
                .append("dns_successful_query_handling_seconds_count ")
                .append(snapshot.resolvedRequests())
                .append('\n');
    }

    private static void appendGauge(
            StringBuilder output,
            String name,
            String help,
            long value
    ) {

        output.append("# HELP ").append(name).append(' ')
                .append(help).append('\n')
                .append("# TYPE ").append(name).append(" gauge\n")
                .append(name).append(' ').append(value).append('\n');
    }

    private static void appendCounter(
            StringBuilder output,
            String name,
            String help,
            long value
    ) {

        output.append("# HELP ").append(name).append(' ')
                .append(help).append('\n')
                .append("# TYPE ").append(name).append(" counter\n")
                .append(name).append(' ').append(value).append('\n');
    }

    private static void appendLabeledCounter(
            StringBuilder output,
            String name,
            String reason,
            long value
    ) {
        appendLabeledValue(output, name, "reason", reason, value);
    }

    private static void appendLabeledValue(
            StringBuilder output,
            String name,
            String labelName,
            String labelValue,
            long value
    ) {
        output.append(name)
                .append('{')
                .append(labelName)
                .append("=\"")
                .append(labelValue)
                .append("\"} ")
                .append(value)
                .append('\n');
    }
}
