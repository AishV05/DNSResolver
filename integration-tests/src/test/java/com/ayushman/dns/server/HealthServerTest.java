package com.ayushman.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;

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
