package com.ayushman.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import com.ayushman.dns.policy.DnsPolicySnapshot;
import org.junit.jupiter.api.Test;

public class HealthServerTest {

    @Test
    void shouldReportReadinessAndMetrics()
            throws Exception {

        AtomicBoolean running = new AtomicBoolean(false);
        ServerMetrics metrics = new ServerMetrics();
        metrics.recordReceivedRequest();
        metrics.recordAdmittedRequest();

        try (HealthServer healthServer = new HealthServer(
                0,
                running::get,
                metrics::snapshot
        )) {
            healthServer.start();

            HttpResponse notReady = request(healthServer.port());

            assertEquals(503, notReady.statusCode());
            assertTrue(notReady.body().contains("\"status\":\"DOWN\""));

            running.set(true);

            HttpResponse ready = request(healthServer.port());

            assertEquals(200, ready.statusCode());
            assertTrue(ready.body().contains("\"status\":\"UP\""));
            assertTrue(ready.body().contains("\"receivedRequests\":1"));
            assertTrue(ready.body().contains("\"admittedRequests\":1"));
            assertTrue(ready.body().contains("\"udpListener\":\"UP\""));
            assertTrue(ready.body().contains("\"tcpListener\":\"UP\""));
            assertTrue(ready.body().contains(
                    "\"policyMode\":\"DISABLED\""
            ));
            assertTrue(ready.body().contains("\"policyReady\":true"));
        }
    }

    @Test
    void reportsRequiredPolicyReadinessAndKeepsLastKnownGoodReady()
            throws Exception {
        ServerMetrics metrics = new ServerMetrics();
        PolicySnapshotStore store = new PolicySnapshotStore(
                PolicySyncMode.REQUIRED
        );
        PolicyTelemetry telemetry = new PolicyTelemetry(
                PolicySyncMode.REQUIRED,
                60_000,
                Clock.fixed(
                        Instant.parse("2026-10-05T00:00:00Z"),
                        ZoneOffset.UTC
                )
        );

        try (HealthServer healthServer = new HealthServer(
                0,
                store::isReady,
                () -> true,
                () -> true,
                metrics::snapshot,
                () -> telemetry.snapshot(store.snapshotStatus())
        )) {
            healthServer.start();

            HttpResponse waiting = request(healthServer.port());
            assertEquals(503, waiting.statusCode());
            assertTrue(waiting.body().contains(
                    "\"policySyncState\":\"AWAITING_INITIAL_SNAPSHOT\""
            ));
            assertTrue(waiting.body().contains("\"policyRevision\":null"));

            store.activate(new DnsPolicySnapshot(
                    0,
                    Instant.parse("2026-10-05T00:00:00Z"),
                    List.of()
            ));
            telemetry.recordSyncAttempt();
            telemetry.recordSyncActivated();

            HttpResponse healthy = request(healthServer.port());
            assertEquals(200, healthy.statusCode());
            assertTrue(healthy.body().contains(
                    "\"policySyncState\":\"HEALTHY\""
            ));
            assertTrue(healthy.body().contains("\"policyRevision\":0"));

            telemetry.recordSyncAttempt();
            telemetry.recordSyncFailure();

            HttpResponse degraded = request(healthServer.port());
            assertEquals(200, degraded.statusCode());
            assertTrue(degraded.body().contains(
                    "\"policySyncState\":\"DEGRADED\""
            ));
            assertTrue(degraded.body().contains(
                    "\"policySyncConsecutiveFailures\":1"
            ));
        }
    }

    @Test
    void shouldRemainDownUntilBothTransportsAreRunning()
            throws Exception {
        AtomicBoolean udpRunning = new AtomicBoolean(true);
        AtomicBoolean tcpRunning = new AtomicBoolean(false);
        ServerMetrics metrics = new ServerMetrics();

        try (HealthServer healthServer = new HealthServer(
                0,
                () -> udpRunning.get() && tcpRunning.get(),
                udpRunning::get,
                tcpRunning::get,
                metrics::snapshot
        )) {
            healthServer.start();

            HttpResponse partial = request(healthServer.port());
            assertEquals(503, partial.statusCode());
            assertTrue(partial.body().contains("\"udpListener\":\"UP\""));
            assertTrue(partial.body().contains("\"tcpListener\":\"DOWN\""));

            tcpRunning.set(true);
            assertEquals(200, request(healthServer.port()).statusCode());
        }
    }

    private HttpResponse request(
            int port
    ) throws Exception {

        HttpURLConnection connection = (HttpURLConnection) URI.create(
                "http://127.0.0.1:" + port + "/health"
        ).toURL().openConnection();

        int statusCode = connection.getResponseCode();
        InputStream input = statusCode >= 400
                ? connection.getErrorStream()
                : connection.getInputStream();

        try (input) {
            return new HttpResponse(
                    statusCode,
                    new String(
                            input.readAllBytes(),
                            StandardCharsets.UTF_8
                    )
            );
        }
    }

    private record HttpResponse(
            int statusCode,
            String body
    ) {
    }
}
