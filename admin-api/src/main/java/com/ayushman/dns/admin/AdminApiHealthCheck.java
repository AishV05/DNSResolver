package com.ayushman.dns.admin;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;

/**
 * Minimal command-line probe used by the Admin API container health check.
 */
public final class AdminApiHealthCheck {

    private static final int DEFAULT_PORT = 8_081;

    private AdminApiHealthCheck() {
    }

    public static void main(String[] args) {
        int port = args.length == 0
                ? DEFAULT_PORT
                : Integer.parseInt(args[0]);

        if (!isHealthy(port)) {
            System.exit(1);
        }
    }

    static boolean isHealthy(int port) {
        HttpURLConnection connection = null;

        try {
            URL endpoint = URI.create(
                    "http://127.0.0.1:" + port + "/actuator/health"
            ).toURL();
            connection = (HttpURLConnection) endpoint.openConnection();
            connection.setConnectTimeout(2_000);
            connection.setReadTimeout(2_000);
            connection.setRequestMethod("GET");

            return isHealthyResponseCode(connection.getResponseCode());
        } catch (IOException exception) {
            return false;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    static boolean isHealthyResponseCode(int responseCode) {
        return responseCode == HttpURLConnection.HTTP_OK;
    }
}
