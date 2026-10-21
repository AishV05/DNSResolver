package com.ayushman.dns.server;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.BooleanSupplier;
import java.util.function.Supplier;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

/**
 * Loopback-only HTTP endpoint for container and process health checks.
 */
public final class HealthServer implements AutoCloseable {

    private final HttpServer server;
    private final ExecutorService executor;
    private final BooleanSupplier dnsRunning;
    private final BooleanSupplier udpRunning;
    private final BooleanSupplier tcpRunning;
    private final Supplier<ServerMetrics.Snapshot> metricsSnapshot;
    private final Supplier<PolicyTelemetry.Snapshot> policySnapshot;

    public HealthServer(
            int port,
            UdpDnsServer dnsServer
    ) throws IOException {

        this(
                port,
                requireServer(dnsServer)::isRunning,
                requireServer(dnsServer).metrics()::snapshot,
                () -> PolicyTelemetry.Snapshot.disabled()
        );
    }

    public HealthServer(
            int port,
            DnsServer dnsServer
    ) throws IOException {
        this(
                port,
                requireServer(dnsServer)::isRunning,
                requireServer(dnsServer)::isUdpRunning,
                requireServer(dnsServer)::isTcpRunning,
                requireServer(dnsServer).metrics()::snapshot,
                requireServer(dnsServer)::policyTelemetrySnapshot
        );
    }

    HealthServer(
            int port,
            BooleanSupplier dnsRunning,
            Supplier<ServerMetrics.Snapshot> metricsSnapshot
    ) throws IOException {
        this(
                port,
                dnsRunning,
                metricsSnapshot,
                () -> PolicyTelemetry.Snapshot.disabled()
        );
    }

    HealthServer(
            int port,
            BooleanSupplier dnsRunning,
            Supplier<ServerMetrics.Snapshot> metricsSnapshot,
            Supplier<PolicyTelemetry.Snapshot> policySnapshot
    ) throws IOException {
        this(
                port,
                dnsRunning,
                dnsRunning,
                dnsRunning,
                metricsSnapshot,
                policySnapshot
        );
    }

    HealthServer(
            int port,
            BooleanSupplier dnsRunning,
            BooleanSupplier udpRunning,
            BooleanSupplier tcpRunning,
            Supplier<ServerMetrics.Snapshot> metricsSnapshot
    ) throws IOException {
        this(
                port,
                dnsRunning,
                udpRunning,
                tcpRunning,
                metricsSnapshot,
                () -> PolicyTelemetry.Snapshot.disabled()
        );
    }

    HealthServer(
            int port,
            BooleanSupplier dnsRunning,
            BooleanSupplier udpRunning,
            BooleanSupplier tcpRunning,
            Supplier<ServerMetrics.Snapshot> metricsSnapshot,
            Supplier<PolicyTelemetry.Snapshot> policySnapshot
    ) throws IOException {

        if (port < 0 || port > 65_535) {
            throw new IllegalArgumentException(
                    "port must be between 0 and 65535"
            );
        }

        if (dnsRunning == null
                || udpRunning == null
                || tcpRunning == null
                || metricsSnapshot == null
                || policySnapshot == null) {
            throw new IllegalArgumentException(
                    "health dependencies must not be null"
            );
        }

        this.dnsRunning = dnsRunning;
        this.udpRunning = udpRunning;
        this.tcpRunning = tcpRunning;
        this.metricsSnapshot = metricsSnapshot;
        this.policySnapshot = policySnapshot;
        this.server = HttpServer.create(
                new InetSocketAddress(
                        InetAddress.getLoopbackAddress(),
                        port
                ),
                0
        );
        this.executor = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "dns-health");
            thread.setDaemon(true);
            return thread;
        });
        this.server.setExecutor(executor);
        this.server.createContext("/health", this::handleHealth);
    }

    public void start() {
        server.start();
    }

    int port() {
        return server.getAddress().getPort();
    }

    @Override
    public void close() {
        server.stop(0);
        executor.shutdownNow();
    }

    private void handleHealth(
            HttpExchange exchange
    ) throws IOException {

        if (!"GET".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            exchange.close();
            return;
        }

        if (!"/health".equals(exchange.getRequestURI().getPath())) {
            exchange.sendResponseHeaders(404, -1);
            exchange.close();
            return;
        }

        ServerMetrics.Snapshot snapshot = metricsSnapshot.get();
        PolicyTelemetry.Snapshot policy = policySnapshot.get();
        boolean ready = dnsRunning.getAsBoolean();
        String status = ready ? "UP" : "DOWN";
        String policyRevision = policy.snapshotLoaded()
                ? Long.toString(policy.revision())
                : "null";
        String lastSuccessfulSync = policy.lastSuccessTimestampSeconds() > 0
                ? Long.toString(policy.lastSuccessTimestampSeconds())
                : "null";
        byte[] response = String.format(
                "{\"status\":\"%s\",\"receivedRequests\":%d,"
                        + "\"admittedRequests\":%d,"
                        + "\"resolverFailures\":%d,"
                        + "\"udpListener\":\"%s\","
                        + "\"tcpListener\":\"%s\","
                        + "\"policyMode\":\"%s\","
                        + "\"policyReady\":%s,"
                        + "\"policySyncState\":\"%s\","
                        + "\"policySnapshotLoaded\":%s,"
                        + "\"policyRevision\":%s,"
                        + "\"policyRuleCount\":%d,"
                        + "\"policySyncConsecutiveFailures\":%d,"
                        + "\"policyLastSuccessfulSyncEpochSeconds\":%s}",
                status,
                snapshot.receivedRequests(),
                snapshot.admittedRequests(),
                snapshot.resolverFailures(),
                udpRunning.getAsBoolean() ? "UP" : "DOWN",
                tcpRunning.getAsBoolean() ? "UP" : "DOWN",
                policy.mode(),
                policy.ready(),
                policy.syncState(),
                policy.snapshotLoaded(),
                policyRevision,
                policy.ruleCount(),
                policy.consecutiveFailures(),
                lastSuccessfulSync
        ).getBytes(StandardCharsets.UTF_8);

        exchange.getResponseHeaders().set(
                "Content-Type",
                "application/json; charset=utf-8"
        );
        exchange.sendResponseHeaders(ready ? 200 : 503, response.length);

        try (OutputStream output = exchange.getResponseBody()) {
            output.write(response);
        }
    }

    private static UdpDnsServer requireServer(
            UdpDnsServer dnsServer
    ) {

        if (dnsServer == null) {
            throw new IllegalArgumentException(
                    "dnsServer must not be null"
            );
        }

        return dnsServer;
    }

    private static DnsServer requireServer(
            DnsServer dnsServer
    ) {
        if (dnsServer == null) {
            throw new IllegalArgumentException(
                    "dnsServer must not be null"
            );
        }

        return dnsServer;
    }
}
