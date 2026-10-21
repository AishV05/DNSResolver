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
 * HTTP endpoint that exposes DNS operational metrics for Prometheus scraping.
 */
public final class MetricsServer implements AutoCloseable {

    private final HttpServer server;
    private final ExecutorService executor;
    private final BooleanSupplier dnsRunning;
    private final BooleanSupplier udpRunning;
    private final BooleanSupplier tcpRunning;
    private final Supplier<ServerMetrics.Snapshot> metricsSnapshot;
    private final Supplier<PolicyTelemetry.Snapshot> policySnapshot;

    public MetricsServer(
            int port,
            String bindAddress,
            UdpDnsServer dnsServer
    ) throws IOException {

        this(
                port,
                bindAddress,
                requireServer(dnsServer)::isRunning,
                requireServer(dnsServer).metrics()::snapshot,
                () -> PolicyTelemetry.Snapshot.disabled()
        );
    }

    public MetricsServer(
            int port,
            String bindAddress,
            DnsServer dnsServer
    ) throws IOException {
        this(
                port,
                bindAddress,
                requireServer(dnsServer)::isRunning,
                requireServer(dnsServer)::isUdpRunning,
                requireServer(dnsServer)::isTcpRunning,
                requireServer(dnsServer).metrics()::snapshot,
                requireServer(dnsServer)::policyTelemetrySnapshot
        );
    }

    MetricsServer(
            int port,
            String bindAddress,
            BooleanSupplier dnsRunning,
            Supplier<ServerMetrics.Snapshot> metricsSnapshot
    ) throws IOException {
        this(
                port,
                bindAddress,
                dnsRunning,
                metricsSnapshot,
                () -> PolicyTelemetry.Snapshot.disabled()
        );
    }

    MetricsServer(
            int port,
            String bindAddress,
            BooleanSupplier dnsRunning,
            Supplier<ServerMetrics.Snapshot> metricsSnapshot,
            Supplier<PolicyTelemetry.Snapshot> policySnapshot
    ) throws IOException {
        this(
                port,
                bindAddress,
                dnsRunning,
                dnsRunning,
                dnsRunning,
                metricsSnapshot,
                policySnapshot
        );
    }

    MetricsServer(
            int port,
            String bindAddress,
            BooleanSupplier dnsRunning,
            BooleanSupplier udpRunning,
            BooleanSupplier tcpRunning,
            Supplier<ServerMetrics.Snapshot> metricsSnapshot
    ) throws IOException {
        this(
                port,
                bindAddress,
                dnsRunning,
                udpRunning,
                tcpRunning,
                metricsSnapshot,
                () -> PolicyTelemetry.Snapshot.disabled()
        );
    }

    MetricsServer(
            int port,
            String bindAddress,
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

        if (bindAddress == null || bindAddress.isBlank()) {
            throw new IllegalArgumentException(
                    "bindAddress must not be blank"
            );
        }

        if (dnsRunning == null
                || udpRunning == null
                || tcpRunning == null
                || metricsSnapshot == null
                || policySnapshot == null) {
            throw new IllegalArgumentException(
                    "metrics dependencies must not be null"
            );
        }

        this.dnsRunning = dnsRunning;
        this.udpRunning = udpRunning;
        this.tcpRunning = tcpRunning;
        this.metricsSnapshot = metricsSnapshot;
        this.policySnapshot = policySnapshot;
        this.server = HttpServer.create(
                new InetSocketAddress(
                        InetAddress.getByName(bindAddress),
                        port
                ),
                0
        );
        this.executor = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "dns-metrics-http");
            thread.setDaemon(true);
            return thread;
        });
        this.server.setExecutor(executor);
        this.server.createContext("/metrics", this::handleMetrics);
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

    private void handleMetrics(
            HttpExchange exchange
    ) throws IOException {

        if (!"GET".equals(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            exchange.close();
            return;
        }

        if (!"/metrics".equals(exchange.getRequestURI().getPath())) {
            exchange.sendResponseHeaders(404, -1);
            exchange.close();
            return;
        }

        String body = PrometheusMetricsFormatter.format(
                dnsRunning.getAsBoolean(),
                udpRunning.getAsBoolean(),
                tcpRunning.getAsBoolean(),
                metricsSnapshot.get(),
                policySnapshot.get()
        );
        byte[] response = body.getBytes(StandardCharsets.UTF_8);

        exchange.getResponseHeaders().set(
                "Content-Type",
                PrometheusMetricsFormatter.CONTENT_TYPE
        );
        exchange.getResponseHeaders().set("Cache-Control", "no-store");
        exchange.sendResponseHeaders(200, response.length);

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
