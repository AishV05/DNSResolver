package com.ayushman.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import com.ayushman.dns.policy.DnsPolicyAction;
import com.ayushman.dns.policy.DnsPolicyMatchType;
import com.ayushman.dns.policy.DnsPolicyRule;
import com.ayushman.dns.policy.DnsPolicySnapshot;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ResolverFleetReporterTest {

    private static final String TOKEN_ONE =
            "abcdefghijklmnopqrstuvwxyz-ABCDEFG_1234567890";
    private static final String TOKEN_TWO =
            "ZYXWVUTSRQPONMLKJIHGFEDCBA-9876543210_abcdef";
    private static final UUID BOOT_ID = UUID.fromString(
            "10000000-0000-0000-0000-000000000001"
    );
    private static final UUID SESSION_ID = UUID.fromString(
            "20000000-0000-0000-0000-000000000002"
    );

    @TempDir
    private Path temporaryDirectory;

    @Test
    void rejectsNullConfigurationWithAContractError() {
        PolicySnapshotStore store = new PolicySnapshotStore(
                PolicySyncMode.DISABLED
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> new ResolverFleetReporter(
                        null,
                        store,
                        PolicyTelemetry.forMode(PolicySyncMode.DISABLED)
                )
        );
    }

    @Test
    void establishesSessionRetriesIdenticalReportAndReadsRotatedToken()
            throws Exception {
        Path tokenFile = tokenFile(TOKEN_ONE);
        List<String> reportBodies = new ArrayList<>();
        List<String> authorizations = new ArrayList<>();
        AtomicInteger reportRequests = new AtomicInteger();
        AtomicReference<String> sessionBody = new AtomicReference<>();

        try (TestControlPlane endpoint = new TestControlPlane()) {
            endpoint.context("/api/v1/internal/resolver/session", exchange -> {
                authorizations.add(authorization(exchange));
                sessionBody.set(body(exchange));
                sendJson(exchange, 201, leaseJson());
            });
            endpoint.context("/api/v1/internal/resolver/report", exchange -> {
                authorizations.add(authorization(exchange));
                reportBodies.add(body(exchange));
                if (reportRequests.incrementAndGet() == 1) {
                    exchange.sendResponseHeaders(503, -1);
                    exchange.close();
                } else {
                    exchange.sendResponseHeaders(204, -1);
                    exchange.close();
                }
            });

            PolicySnapshotStore store = new PolicySnapshotStore(
                    PolicySyncMode.REQUIRED
            );
            PolicyTelemetry policyTelemetry = new PolicyTelemetry(
                    PolicySyncMode.REQUIRED,
                    60_000,
                    Clock.fixed(Instant.parse("2026-01-01T00:00:00Z"),
                            ZoneOffset.UTC)
            );
            ResolverReportingTelemetry reportingTelemetry =
                    new ResolverReportingTelemetry(
                            ResolverReportingMode.ENABLED,
                            Clock.fixed(
                                    Instant.parse("2026-01-01T00:00:00Z"),
                                    ZoneOffset.UTC
                            )
                    );

            try (ResolverFleetReporter reporter = reporter(
                    endpoint.uri(),
                    tokenFile,
                    store,
                    policyTelemetry,
                    reportingTelemetry
            )) {
                assertEquals(
                        ResolverFleetReporter.ReportingResult.SESSION_ESTABLISHED,
                        reporter.reportOnce()
                );
                assertTrue(sessionBody.get().contains(
                        "\"applicationVersion\":\"0.1.0\""
                ));
                assertNotNull(reporter.currentLease());

                assertThrows(IOException.class, reporter::reportOnce);
                String pendingBody = reportBodies.get(0);
                assertTrue(pendingBody.contains("\"sequence\":1"));
                assertTrue(pendingBody.contains(
                        "\"policySnapshotLoaded\":false"
                ));

                store.activate(new DnsPolicySnapshot(
                        1,
                        0,
                        Instant.parse("2026-01-01T00:00:00Z"),
                        List.of(new DnsPolicyRule(
                                "blocked.example",
                                DnsPolicyMatchType.EXACT,
                                DnsPolicyAction.BLOCK
                        ))
                ));
                policyTelemetry.recordSyncAttempt();
                policyTelemetry.recordSyncActivated();
                Files.writeString(tokenFile, TOKEN_TWO);

                assertEquals(
                        ResolverFleetReporter.ReportingResult.REPORT_ACCEPTED,
                        reporter.reportOnce()
                );
                assertEquals(pendingBody, reportBodies.get(1));

                assertEquals(
                        ResolverFleetReporter.ReportingResult.REPORT_ACCEPTED,
                        reporter.reportOnce()
                );
                String nextBody = reportBodies.get(2);
                assertTrue(nextBody.contains("\"sequence\":2"));
                assertTrue(nextBody.contains(
                        "\"policySnapshotLoaded\":true"
                ));
                assertTrue(nextBody.contains("\"policyRevision\":0"));
                assertTrue(nextBody.contains("\"policyRuleCount\":1"));

                assertEquals("Bearer " + TOKEN_ONE, authorizations.get(0));
                assertEquals("Bearer " + TOKEN_ONE, authorizations.get(1));
                assertEquals("Bearer " + TOKEN_TWO, authorizations.get(2));
                assertEquals("Bearer " + TOKEN_TWO, authorizations.get(3));

                ResolverReportingTelemetry.Snapshot metrics =
                        reporter.telemetrySnapshot();
                assertEquals(4, metrics.attempts());
                assertEquals(1, metrics.sessionsEstablished());
                assertEquals(2, metrics.reportsAccepted());
                assertEquals(1, metrics.failures());
                assertEquals(
                        ResolverReportingTelemetry.State.ACTIVE,
                        metrics.state()
                );
            }
        }
    }

    @Test
    void stopsAfterControlPlaneFencesTheSession() throws Exception {
        Path tokenFile = tokenFile(TOKEN_ONE);
        AtomicInteger reportRequests = new AtomicInteger();

        try (TestControlPlane endpoint = new TestControlPlane()) {
            endpoint.context(
                    "/api/v1/internal/resolver/session",
                    exchange -> sendJson(exchange, 200, leaseJson())
            );
            endpoint.context("/api/v1/internal/resolver/report", exchange -> {
                reportRequests.incrementAndGet();
                body(exchange);
                exchange.sendResponseHeaders(409, -1);
                exchange.close();
            });

            PolicySnapshotStore store = new PolicySnapshotStore(
                    PolicySyncMode.DISABLED
            );
            PolicyTelemetry policyTelemetry = PolicyTelemetry.forMode(
                    PolicySyncMode.DISABLED
            );
            ResolverReportingTelemetry reportingTelemetry =
                    new ResolverReportingTelemetry(ResolverReportingMode.ENABLED);

            try (ResolverFleetReporter reporter = reporter(
                    endpoint.uri(),
                    tokenFile,
                    store,
                    policyTelemetry,
                    reportingTelemetry
            )) {
                reporter.reportOnce();
                assertThrows(
                        ResolverFleetReporter.FencedSessionException.class,
                        reporter::reportOnce
                );
                assertTrue(reporter.isFenced());
                assertThrows(IllegalStateException.class, reporter::reportOnce);
                assertEquals(1, reportRequests.get());
                assertEquals(
                        ResolverReportingTelemetry.State.FENCED,
                        reporter.telemetrySnapshot().state()
                );
            }
        }
    }

    @Test
    void disabledReporterStartsWithoutNetworkOrReadinessEffects()
            throws Exception {
        ResolverReportingConfig config = ResolverReportingConfig.from(
                new java.util.Properties(),
                java.util.Map.of()
        );
        PolicySnapshotStore store = new PolicySnapshotStore(
                PolicySyncMode.DISABLED
        );
        try (ResolverFleetReporter reporter = new ResolverFleetReporter(
                config,
                store,
                PolicyTelemetry.forMode(PolicySyncMode.DISABLED)
        )) {
            reporter.start();
            assertEquals(
                    ResolverReportingTelemetry.State.DISABLED,
                    reporter.telemetrySnapshot().state()
            );
            assertEquals(0, reporter.telemetrySnapshot().attempts());
            assertTrue(store.isReady());
        }
    }

    @Test
    void calculatesBoundedBackoffWithDeterministicJitter()
            throws Exception {
        Path tokenFile = tokenFile(TOKEN_ONE);
        try (TestControlPlane endpoint = new TestControlPlane()) {
            PolicySnapshotStore store = new PolicySnapshotStore(
                    PolicySyncMode.DISABLED
            );
            ResolverReportingConfig config = config(endpoint.uri(), tokenFile);
            try (ResolverFleetReporter reporter = new ResolverFleetReporter(
                    config,
                    store,
                    PolicyTelemetry.forMode(PolicySyncMode.DISABLED),
                    new ResolverReportingTelemetry(ResolverReportingMode.ENABLED),
                    HttpClient.newHttpClient(),
                    Executors.newSingleThreadScheduledExecutor(),
                    () -> 0.5,
                    BOOT_ID
            )) {
                assertEquals(100, reporter.retryDelayMillis(1));
                assertEquals(200, reporter.retryDelayMillis(2));
                assertEquals(400, reporter.retryDelayMillis(3));
                assertEquals(500, reporter.retryDelayMillis(4));
                assertEquals(500, reporter.retryDelayMillis(100));
            }
        }
    }

    private ResolverFleetReporter reporter(
            URI controlPlane,
            Path tokenFile,
            PolicySnapshotStore store,
            PolicyTelemetry policyTelemetry,
            ResolverReportingTelemetry reportingTelemetry
    ) {
        return new ResolverFleetReporter(
                config(controlPlane, tokenFile),
                store,
                policyTelemetry,
                reportingTelemetry,
                HttpClient.newBuilder()
                        .connectTimeout(java.time.Duration.ofMillis(500))
                        .build(),
                Executors.newSingleThreadScheduledExecutor(),
                () -> 0.5,
                BOOT_ID
        );
    }

    private ResolverReportingConfig config(URI endpoint, Path tokenFile) {
        return new ResolverReportingConfig(
                ResolverReportingMode.ENABLED,
                endpoint,
                tokenFile,
                "0.1.0",
                true,
                500,
                1_000,
                1_000,
                100,
                500,
                4_096
        );
    }

    private Path tokenFile(String token) throws IOException {
        Path path = temporaryDirectory.resolve("resolver-token");
        Files.writeString(path, token);
        return path.toAbsolutePath();
    }

    private String leaseJson() {
        return """
                {"schemaVersion":1,"resolverId":"resolver-a",
                 "sessionId":"%s","bootId":"%s","sessionGeneration":3}
                """.formatted(SESSION_ID, BOOT_ID);
    }

    private static String authorization(HttpExchange exchange) {
        return exchange.getRequestHeaders().getFirst("Authorization");
    }

    private static String body(HttpExchange exchange) throws IOException {
        try (var input = exchange.getRequestBody()) {
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private static void sendJson(
            HttpExchange exchange,
            int status,
            String json
    ) throws IOException {
        byte[] response = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set(
                "Content-Type",
                "application/json; charset=utf-8"
        );
        exchange.sendResponseHeaders(status, response.length);
        exchange.getResponseBody().write(response);
        exchange.close();
    }

    private static final class TestControlPlane implements AutoCloseable {
        private final HttpServer server;

        private TestControlPlane() throws IOException {
            server = HttpServer.create(
                    new InetSocketAddress(
                            InetAddress.getLoopbackAddress(),
                            0
                    ),
                    0
            );
            server.start();
        }

        private void context(
                String path,
                com.sun.net.httpserver.HttpHandler handler
        ) {
            server.createContext(path, handler);
        }

        private URI uri() {
            return URI.create(
                    "http://127.0.0.1:" + server.getAddress().getPort()
            );
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }
}
