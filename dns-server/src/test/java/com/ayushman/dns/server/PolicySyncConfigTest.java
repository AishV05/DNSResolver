package com.ayushman.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;
import java.util.Map;
import java.util.Properties;

import org.junit.jupiter.api.Test;

class PolicySyncConfigTest {

    @Test
    void defaultsToDisabledWithoutAControlPlaneDependency() {
        PolicySyncConfig config = PolicySyncConfig.from(
                new Properties(),
                Map.of()
        );

        assertEquals(PolicySyncMode.DISABLED, config.mode());
        assertEquals(null, config.snapshotUri());
        assertEquals(null, config.tokenFile());
        assertFalse(config.allowInsecureHttp());
        assertEquals(10_000, config.maxRules());
        PolicyTelemetry telemetry = PolicyTelemetry.fromConfig(config);
        PolicySnapshotStore store = new PolicySnapshotStore(config.mode());
        assertEquals(
                95,
                telemetry.snapshot(store.snapshotStatus())
                        .staleAfterSeconds()
        );
    }

    @Test
    void loadsRequiredModeAndPrefersSystemProperties() {
        Properties properties = new Properties();
        properties.setProperty("dns.policy.mode", "required");
        properties.setProperty(
                "dns.policy.snapshotUrl",
                "https://policy.example/api/v1/internal/policy-snapshot"
        );
        properties.setProperty("dns.policy.maxRules", "250");

        PolicySyncConfig config = PolicySyncConfig.from(
                properties,
                Map.of(
                        "DNS_POLICY_MODE", "disabled",
                        "DNS_POLICY_TOKEN_FILE", "/run/secrets/policy-token",
                        "DNS_POLICY_MAX_RULES", "999"
                )
        );

        assertEquals(PolicySyncMode.REQUIRED, config.mode());
        assertEquals(
                "https://policy.example/api/v1/internal/policy-snapshot",
                config.snapshotUri().toString()
        );
        assertEquals(
                Path.of("/run/secrets/policy-token"),
                config.tokenFile()
        );
        assertEquals(250, config.maxRules());
    }

    @Test
    void rejectsUnsafeOrIncompleteRequiredConfiguration() {
        Properties requiredOnly = new Properties();
        requiredOnly.setProperty("dns.policy.mode", "required");
        assertThrows(
                IllegalArgumentException.class,
                () -> PolicySyncConfig.from(requiredOnly, Map.of())
        );

        Properties insecure = requiredProperties();
        insecure.setProperty(
                "dns.policy.snapshotUrl",
                "http://admin-api:8081/api/v1/internal/policy-snapshot"
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> PolicySyncConfig.from(insecure, Map.of())
        );

        Properties wrongPath = requiredProperties();
        wrongPath.setProperty(
                "dns.policy.snapshotUrl",
                "https://policy.example/api/v1/admin/policies"
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> PolicySyncConfig.from(wrongPath, Map.of())
        );

        Properties relativeToken = requiredProperties();
        relativeToken.setProperty("dns.policy.tokenFile", "token.txt");
        assertThrows(
                IllegalArgumentException.class,
                () -> PolicySyncConfig.from(relativeToken, Map.of())
        );
    }

    @Test
    void permitsPlainHttpOnlyWithAnExplicitOptIn() {
        Properties properties = requiredProperties();
        properties.setProperty(
                "dns.policy.snapshotUrl",
                "http://127.0.0.1:8081/api/v1/internal/policy-snapshot"
        );
        properties.setProperty("dns.policy.allowInsecureHttp", "true");

        PolicySyncConfig config = PolicySyncConfig.from(
                properties,
                Map.of()
        );

        assertEquals("http", config.snapshotUri().getScheme());
        assertEquals(true, config.allowInsecureHttp());
    }

    private Properties requiredProperties() {
        Properties properties = new Properties();
        properties.setProperty("dns.policy.mode", "required");
        properties.setProperty(
                "dns.policy.snapshotUrl",
                "https://policy.example/api/v1/internal/policy-snapshot"
        );
        properties.setProperty(
                "dns.policy.tokenFile",
                "/run/secrets/policy-token"
        );
        return properties;
    }
}
