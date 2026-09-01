package com.ayushman.dns.server;

import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;

/**
 * Minimal command-line probe used by the container health check.
 */
public final class HealthCheck {

    private HealthCheck() {
    }

    public static void main(String[] args)
            throws Exception {

        int port = args.length == 0
                ? 8_080
                : Integer.parseInt(args[0]);

        URL endpoint = URI.create(
                "http://127.0.0.1:" + port + "/health"
        ).toURL();
        HttpURLConnection connection =
                (HttpURLConnection) endpoint.openConnection();

        connection.setConnectTimeout(2_000);
        connection.setReadTimeout(2_000);
        connection.setRequestMethod("GET");

        int responseCode = connection.getResponseCode();
        connection.disconnect();

        if (responseCode != 200) {
            System.exit(1);
        }
    }
}
