package com.ayushman.dns.admin;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;

/**
 * Shared external credentials for real HTTP tests. These test-only values are
 * never packaged into the application artifact.
 */
public final class AdminApiTestAuthentication {

    public static final String BOOTSTRAP_TOKEN =
            "test-bootstrap-token-at-least-thirty-two-characters";

    private AdminApiTestAuthentication() {
    }

    public static HttpHeaders bearerHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(BOOTSTRAP_TOKEN);
        return headers;
    }

    public static <T> HttpEntity<T> authenticated(T body) {
        return new HttpEntity<>(body, bearerHeaders());
    }

    public static HttpEntity<Void> authenticated() {
        return new HttpEntity<>(bearerHeaders());
    }
}
