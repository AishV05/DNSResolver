package com.ayushman.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicBoolean;

import org.junit.jupiter.api.Test;

class MetricsServerTest {

    @Test
    void exposesPrometheusMetricsAndRejectsUnsupportedMethods()
            throws Exception {

        AtomicBoolean running = new AtomicBoolean(true);
        ServerMetrics metrics = new ServerMetrics();
        metrics.recordReceivedRequest();
        metrics.recordResolvedRequest(1_000_000);

        try (MetricsServer metricsServer = new MetricsServer(
                0,
                "127.0.0.1",
                running::get,
                metrics::snapshot
        )) {
            metricsServer.start();

            HttpResponse response = request(metricsServer.port(), "GET");

            assertEquals(200, response.statusCode());
            assertTrue(response.contentType().startsWith(
                    "text/plain; version=0.0.4"
            ));
            assertTrue(response.body().contains(
                    "dns_requests_received_total 1"
            ));
            assertTrue(response.body().contains(
                    "dns_successful_query_handling_seconds_count 1"
            ));
            assertTrue(response.body().contains(
                    "dns_policy_mode{mode=\"disabled\"} 1"
            ));
            assertTrue(response.body().contains("dns_policy_ready 1"));

            assertEquals(
                    405,
                    request(metricsServer.port(), "POST").statusCode()
            );
        }
    }

    private HttpResponse request(
            int port,
            String method
    ) throws Exception {

        HttpURLConnection connection = (HttpURLConnection) URI.create(
                "http://127.0.0.1:" + port + "/metrics"
        ).toURL().openConnection();
        connection.setRequestMethod(method);

        int statusCode = connection.getResponseCode();
        InputStream input = statusCode >= 400
                ? connection.getErrorStream()
                : connection.getInputStream();
        String body = "";

        if (input != null) {
            try (input) {
                body = new String(
                        input.readAllBytes(),
                        StandardCharsets.UTF_8
                );
            }
        }

        String contentType = connection.getContentType();
        connection.disconnect();

        return new HttpResponse(statusCode, contentType, body);
    }

    private record HttpResponse(
            int statusCode,
            String contentType,
            String body
    ) {
    }
}
