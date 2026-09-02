package com.ayushman.dns.admin.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * First-start credentials supplied only from external configuration.
 *
 * <p>The values intentionally have no defaults. They are used only when the
 * identity store is empty and the raw token is never persisted.</p>
 */
@ConfigurationProperties(prefix = "dns.admin.bootstrap")
public class AdminBootstrapProperties {

    private String username = "";
    private String token = "";

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username == null ? "" : username;
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token == null ? "" : token;
    }

    boolean isConfigured() {
        return !username.isBlank() && !token.isBlank();
    }
}
