package com.ayushman.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
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
import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PolicySnapshotSynchronizerTest {

    private static final String TOKEN_ONE =
            "abcdefghijklmnopqrstuvwxyz-ABCDEFG_1234567890";
    private static final String TOKEN_TWO =
            "ZYXWVUTSRQPONMLKJIHGFEDCBA-9876543210_abcdef";

    @TempDir
    private Path temporaryDirectory;

    @Test
    void authenticatesActivatesAndThenUsesConditionalPolling()
            throws Exception {
        Path tokenFile = tokenFile(TOKEN_ONE);
        AtomicReference<String> authorization = new AtomicReference<>();
        AtomicReference<String> ifNoneMatch = new AtomicReference<>();
        AtomicInteger requests = new AtomicInteger();

        try (TestEndpoint endpoint = new TestEndpoint(exchange -> {
            int requestNumber = requests.incrementAndGet();
            authorization.set(exchange.getRequestHeaders().getFirst(
                    "Authorization"
            ));
            ifNoneMatch.set(exchange.getRequestHeaders().getFirst(
                    "If-None-Match"
            ));
            if (requestNumber <= 2) {
                sendSnapshot(exchange, 0, "");
            } else {
                sendNotModified(exchange, "\"policy-v1-r0\"");
            }
        })) {
            PolicySnapshotStore store = requiredStore();
            PolicySyncConfig config = config(endpoint.uri(), tokenFile);
            PolicyTelemetry telemetry = PolicyTelemetry.fromConfig(config);
            try (PolicySnapshotSynchronizer synchronizer =
                    new PolicySnapshotSynchronizer(
                            config,
                            store,
                            telemetry
                    )) {
                assertEquals(
                        PolicySnapshotSynchronizer.SyncResult.ACTIVATED,
                        synchronizer.synchronizeOnce()
                );
                assertTrue(store.isReady());
                assertEquals(
                        0,
                        store.currentSnapshot().orElseThrow().revision()
                );
                assertEquals("Bearer " + TOKEN_ONE, authorization.get());
                assertEquals("\"policy-v1-r0\"", synchronizer.currentEtag());

                assertEquals(
                        PolicySnapshotSynchronizer.SyncResult.UNCHANGED,
                        synchronizer.synchronizeOnce()
                );
                assertEquals("\"policy-v1-r0\"", ifNoneMatch.get());

                Files.writeString(tokenFile, TOKEN_TWO);
                assertEquals(
                        PolicySnapshotSynchronizer.SyncResult.NOT_MODIFIED,
                        synchronizer.synchronizeOnce()
                );
                assertEquals("Bearer " + TOKEN_TWO, authorization.get());

                PolicyTelemetry.Snapshot metrics = telemetry.snapshot(
                        store.snapshotStatus()
                );
                assertEquals(3, metrics.syncAttempts());
                assertEquals(1, metrics.syncActivated());
                assertEquals(1, metrics.syncUnchanged());
                assertEquals(1, metrics.syncNotModified());
                assertEquals(0, metrics.syncFailures());
                assertEquals(0, metrics.consecutiveFailures());
            }
        }
    }

    @Test
    void rejectsRollbackAndMutationWithoutReplacingLastKnownGood()
            throws Exception {
        Path tokenFile = tokenFile(TOKEN_ONE);
        AtomicReference<Response> response = new AtomicReference<>(
                snapshotResponse(5, "blocked.example")
        );

        try (TestEndpoint endpoint = new TestEndpoint(exchange ->
                response.get().send(exchange))) {
            PolicySnapshotStore store = requiredStore();
            try (PolicySnapshotSynchronizer synchronizer =
                    new PolicySnapshotSynchronizer(
                            config(endpoint.uri(), tokenFile),
                            store
                    )) {
                synchronizer.synchronizeOnce();

                response.set(snapshotResponse(4, "older.example"));
                assertThrows(
                        IllegalArgumentException.class,
                        synchronizer::synchronizeOnce
                );
                assertEquals(
                        5,
                        store.currentSnapshot().orElseThrow().revision()
                );
                assertEquals("\"policy-v1-r5\"", synchronizer.currentEtag());

                response.set(snapshotResponse(5, "changed.example"));
                assertThrows(
                        IllegalArgumentException.class,
                        synchronizer::synchronizeOnce
                );
                assertEquals(
                        "blocked.example",
                        store.currentSnapshot()
                                .orElseThrow()
                                .rules()
                                .get(0)
                                .domainName()
                );
            }
        }
    }

    @Test
    void rejectsUnauthorizedMismatchedAndOversizedResponses()
            throws Exception {
        Path tokenFile = tokenFile(TOKEN_ONE);
        AtomicReference<Response> response = new AtomicReference<>(
                exchange -> exchange.sendResponseHeaders(401, -1)
        );

        try (TestEndpoint endpoint = new TestEndpoint(exchange ->
                response.get().send(exchange))) {
            PolicySnapshotStore store = requiredStore();
            PolicySyncConfig config = config(
                    endpoint.uri(),
                    tokenFile,
                    256,
                    10,
                    1_000
            );
            PolicyTelemetry telemetry = PolicyTelemetry.fromConfig(config);
            try (PolicySnapshotSynchronizer synchronizer =
                    new PolicySnapshotSynchronizer(
                            config,
                            store,
                            telemetry
                    )) {
                assertThrows(IOException.class, synchronizer::synchronizeOnce);
                assertFalse(store.isReady());

                response.set(exchange -> sendNotModified(
                        exchange,
                        "\"policy-v1-r0\""
                ));
                assertThrows(IOException.class, synchronizer::synchronizeOnce);
                assertFalse(store.isReady());

                response.set(exchange -> {
                    byte[] body = snapshotJson(1, "one.example");
                    exchange.getResponseHeaders().set(
                            "Content-Type",
                            "application/json"
                    );
                    exchange.getResponseHeaders().set(
                            "ETag",
                            "\"policy-v1-r999\""
                    );
                    exchange.sendResponseHeaders(200, body.length);
                    exchange.getResponseBody().write(body);
                    exchange.close();
                });
                assertThrows(IOException.class, synchronizer::synchronizeOnce);
                assertFalse(store.isReady());

                response.set(exchange -> {
                    byte[] body = "x".repeat(300)
                            .getBytes(StandardCharsets.UTF_8);
                    exchange.getResponseHeaders().set(
                            "Content-Type",
                            "application/json"
                    );
                    exchange.getResponseHeaders().set(
                            "ETag",
                            "\"policy-v1-r1\""
                    );
                    exchange.sendResponseHeaders(200, body.length);
                    exchange.getResponseBody().write(body);
                    exchange.close();
                });
                assertThrows(Exception.class, synchronizer::synchronizeOnce);
                assertFalse(store.isReady());

                PolicyTelemetry.Snapshot metrics = telemetry.snapshot(
                        store.snapshotStatus()
                );
                assertEquals(4, metrics.syncAttempts());
                assertEquals(4, metrics.syncFailures());
                assertEquals(4, metrics.consecutiveFailures());
                assertEquals(
                        PolicyTelemetry.SyncState.AWAITING_INITIAL_SNAPSHOT,
                        metrics.syncState()
                );
            }
        }
    }

    @Test
    void neverFollowsSnapshotEndpointRedirects() throws Exception {
        Path tokenFile = tokenFile(TOKEN_ONE);
        AtomicInteger redirectTargetRequests = new AtomicInteger();

        try (TestEndpoint endpoint = new TestEndpoint(exchange -> {
            exchange.getResponseHeaders().set(
                    "Location",
                    "/redirect-target"
            );
            exchange.sendResponseHeaders(302, -1);
            exchange.close();
        })) {
            endpoint.addContext("/redirect-target", exchange -> {
                redirectTargetRequests.incrementAndGet();
                sendSnapshot(exchange, 1, "redirected.example");
            });
            PolicySnapshotStore store = requiredStore();
            try (PolicySnapshotSynchronizer synchronizer =
                    new PolicySnapshotSynchronizer(
                            config(endpoint.uri(), tokenFile),
                            store
                    )) {
                assertThrows(IOException.class, synchronizer::synchronizeOnce);
                assertEquals(0, redirectTargetRequests.get());
                assertFalse(store.isReady());
            }
        }
    }

    @Test
    void enforcesRequestTimeoutAndRetainsAnAlreadyLoadedSnapshot()
            throws Exception {
        Path tokenFile = tokenFile(TOKEN_ONE);
        AtomicReference<Response> response = new AtomicReference<>(
                snapshotResponse(2, "loaded.example")
        );

        try (TestEndpoint endpoint = new TestEndpoint(exchange ->
                response.get().send(exchange))) {
            PolicySnapshotStore store = requiredStore();
            try (PolicySnapshotSynchronizer synchronizer =
                    new PolicySnapshotSynchronizer(
                            config(
                                    endpoint.uri(),
                                    tokenFile,
                                    4_096,
                                    10,
                                    100
                            ),
                            store
                    )) {
                synchronizer.synchronizeOnce();
                response.set(exchange -> {
                    try {
                        Thread.sleep(300);
                    } catch (InterruptedException interrupted) {
                        Thread.currentThread().interrupt();
                    }
                    sendSnapshot(exchange, 3, "later.example");
                });

                assertThrows(Exception.class, synchronizer::synchronizeOnce);
                assertEquals(
                        2,
                        store.currentSnapshot().orElseThrow().revision()
                );
            }
        }
    }

    @Test
    void backgroundLoopRetriesWithBoundedBackoffAndEventuallyLoads()
            throws Exception {
        Path tokenFile = tokenFile(TOKEN_ONE);
        AtomicInteger requests = new AtomicInteger();
        CountDownLatch successfulResponse = new CountDownLatch(1);

        try (TestEndpoint endpoint = new TestEndpoint(exchange -> {
            if (requests.incrementAndGet() < 3) {
                exchange.sendResponseHeaders(503, -1);
            } else {
                sendSnapshot(exchange, 1, "eventual.example");
                successfulResponse.countDown();
            }
        })) {
            PolicySnapshotStore store = requiredStore();
            PolicySyncConfig config = new PolicySyncConfig(
                    PolicySyncMode.REQUIRED,
                    endpoint.uri(),
                    tokenFile,
                    true,
                    500,
                    1_000,
                    10_000,
                    100,
                    500,
                    4_096,
                    10
            );
            try (PolicySnapshotSynchronizer synchronizer =
                    new PolicySnapshotSynchronizer(config, store)) {
                synchronizer.start();
                assertTrue(successfulResponse.await(3, TimeUnit.SECONDS));
                long deadline = System.nanoTime()
                        + TimeUnit.SECONDS.toNanos(1);
                while (!store.isReady() && System.nanoTime() < deadline) {
                    Thread.sleep(10);
                }
                assertTrue(store.isReady());
                assertTrue(requests.get() >= 3);
            }
        }
    }

    @Test
    void calculatesExponentialBackoffWithDeterministicJitter()
            throws Exception {
        Path tokenFile = tokenFile(TOKEN_ONE);
        try (TestEndpoint endpoint = new TestEndpoint(exchange ->
                exchange.sendResponseHeaders(500, -1))) {
            PolicySyncConfig config = new PolicySyncConfig(
                    PolicySyncMode.REQUIRED,
                    endpoint.uri(),
                    tokenFile,
                    true,
                    500,
                    1_000,
                    10_000,
                    1_000,
                    5_000,
                    4_096,
                    10
            );
            ScheduledExecutorService scheduler =
                    Executors.newSingleThreadScheduledExecutor();
            try (PolicySnapshotSynchronizer synchronizer =
                    new PolicySnapshotSynchronizer(
                            config,
                            requiredStore(),
                            HttpClient.newBuilder()
                                    .connectTimeout(Duration.ofMillis(500))
                                    .build(),
                            scheduler,
                            () -> 0.5
                    )) {
                assertEquals(1_000, synchronizer.retryDelayMillis(1));
                assertEquals(2_000, synchronizer.retryDelayMillis(2));
                assertEquals(4_000, synchronizer.retryDelayMillis(3));
                assertEquals(5_000, synchronizer.retryDelayMillis(4));
                assertEquals(5_000, synchronizer.retryDelayMillis(20));
            }
        }
    }

    private PolicySnapshotStore requiredStore() {
        return new PolicySnapshotStore(PolicySyncMode.REQUIRED);
    }

    private Path tokenFile(String token) throws IOException {
        Path path = temporaryDirectory.resolve("policy-token");
        Files.writeString(path, token);
        return path;
    }

    private PolicySyncConfig config(URI uri, Path tokenFile) {
        return config(uri, tokenFile, 4_096, 10, 1_000);
    }

    private PolicySyncConfig config(
            URI uri,
            Path tokenFile,
            int maxBytes,
            int maxRules,
            int requestTimeoutMillis
    ) {
        return new PolicySyncConfig(
                PolicySyncMode.REQUIRED,
                uri,
                tokenFile,
                true,
                100,
                requestTimeoutMillis,
                1_000,
                100,
                1_000,
                maxBytes,
                maxRules
        );
    }

    private static Response snapshotResponse(long revision, String domain) {
        return exchange -> sendSnapshot(exchange, revision, domain);
    }

    private static void sendSnapshot(
            HttpExchange exchange,
            long revision,
            String domain
    ) throws IOException {
        byte[] body = snapshotJson(revision, domain);
        exchange.getResponseHeaders().set(
                "Content-Type",
                "application/json; charset=utf-8"
        );
        exchange.getResponseHeaders().set(
                "ETag",
                "\"policy-v1-r" + revision + "\""
        );
        exchange.sendResponseHeaders(200, body.length);
        exchange.getResponseBody().write(body);
        exchange.close();
    }

    private static void sendNotModified(
            HttpExchange exchange,
            String etag
    ) throws IOException {
        exchange.getResponseHeaders().set("ETag", etag);
        exchange.sendResponseHeaders(304, -1);
        exchange.close();
    }

    private static byte[] snapshotJson(long revision, String domain) {
        String rules = domain.isEmpty()
                ? ""
                : "{\"domainName\":\"" + domain
                        + "\",\"matchType\":\"EXACT\","
                        + "\"action\":\"BLOCK\"}";
        return ("{\"schemaVersion\":1,\"revision\":"
                + revision
                + ",\"publishedAt\":\"2026-10-04T00:00:00Z\","
                + "\"rules\":["
                + rules
                + "]}").getBytes(StandardCharsets.UTF_8);
    }

    @FunctionalInterface
    private interface Response {
        void send(HttpExchange exchange) throws IOException;
    }

    private static final class TestEndpoint implements AutoCloseable {

        private final HttpServer server;

        private TestEndpoint(HttpHandler handler) throws IOException {
            server = HttpServer.create(
                    new InetSocketAddress(
                            InetAddress.getLoopbackAddress(),
                            0
                    ),
                    0
            );
            server.createContext(
                    "/api/v1/internal/policy-snapshot",
                    handler
            );
            server.start();
        }

        private URI uri() {
            return URI.create(
                    "http://127.0.0.1:"
                            + server.getAddress().getPort()
                            + "/api/v1/internal/policy-snapshot"
            );
        }

        private void addContext(String path, HttpHandler handler) {
            server.createContext(path, handler);
        }

        @Override
        public void close() {
            server.stop(0);
        }
    }
}
