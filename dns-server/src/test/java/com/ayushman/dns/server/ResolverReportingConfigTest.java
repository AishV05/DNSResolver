package com.ayushman.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.file.Path;
import java.util.Map;
import java.util.Properties;

import org.junit.jupiter.api.Test;

class ResolverReportingConfigTest {

    @Test
    void defaultsToDisabledAndRequiresNoControlPlane() {
        ResolverReportingConfig config = ResolverReportingConfig.from(
                new Properties(),
                Map.of()
        );

        assertEquals(ResolverReportingMode.DISABLED, config.mode());
        assertEquals(null, config.controlPlaneUri());
        assertEquals(null, config.tokenFile());
        assertEquals("development", config.applicationVersion());
        assertFalse(config.allowInsecureHttp());
    }

    @Test
    void loadsEnabledConfigurationAndBuildsFixedEndpoints() {
        Properties properties = enabledProperties();
        properties.setProperty("dns.applicationVersion", "0.1.0-SNAPSHOT");
        properties.setProperty("dns.reporting.reportIntervalMillis", "2500");

        ResolverReportingConfig config = ResolverReportingConfig.from(
                properties,
                Map.of()
        );

        assertEquals(ResolverReportingMode.ENABLED, config.mode());
        assertEquals(
                Path.of("/run/secrets/resolver-agent-token"),
                config.tokenFile()
        );
        assertEquals("0.1.0-SNAPSHOT", config.applicationVersion());
        assertEquals(2500, config.reportIntervalMillis());
        assertEquals(
                "https://admin.example/api/v1/internal/resolver/session",
                config.sessionUri().toString()
        );
        assertEquals(
                "https://admin.example/api/v1/internal/resolver/report",
                config.reportUri().toString()
        );
    }

    @Test
    void rejectsIncompleteUnsafeAndAmbiguousOrigins() {
        Properties enabledOnly = new Properties();
        enabledOnly.setProperty("dns.reporting.mode", "enabled");
        assertThrows(
                IllegalArgumentException.class,
                () -> ResolverReportingConfig.from(enabledOnly, Map.of())
        );

        Properties insecure = enabledProperties();
        insecure.setProperty(
                "dns.reporting.controlPlaneUrl",
                "http://admin.example"
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> ResolverReportingConfig.from(insecure, Map.of())
        );

        Properties withPath = enabledProperties();
        withPath.setProperty(
                "dns.reporting.controlPlaneUrl",
                "https://admin.example/api"
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> ResolverReportingConfig.from(withPath, Map.of())
        );

        Properties withCredentials = enabledProperties();
        withCredentials.setProperty(
                "dns.reporting.controlPlaneUrl",
                "https://user:secret@admin.example"
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> ResolverReportingConfig.from(withCredentials, Map.of())
        );

        Properties withInvalidPort = enabledProperties();
        withInvalidPort.setProperty(
                "dns.reporting.controlPlaneUrl",
                "https://admin.example:0"
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> ResolverReportingConfig.from(withInvalidPort, Map.of())
        );

        Properties relativeToken = enabledProperties();
        relativeToken.setProperty("dns.reporting.tokenFile", "token.txt");
        assertThrows(
                IllegalArgumentException.class,
                () -> ResolverReportingConfig.from(relativeToken, Map.of())
        );
    }

    @Test
    void permitsInternalHttpOnlyWithExplicitOptIn() {
        Properties properties = enabledProperties();
        properties.setProperty(
                "dns.reporting.controlPlaneUrl",
                "http://admin-api:8081"
        );
        properties.setProperty("dns.reporting.allowInsecureHttp", "true");

        ResolverReportingConfig config = ResolverReportingConfig.from(
                properties,
                Map.of()
        );

        assertEquals("http", config.controlPlaneUri().getScheme());
    }

    @Test
    void rejectsInvalidVersionAndUnboundedTimingValues() {
        Properties invalidVersion = enabledProperties();
        invalidVersion.setProperty("dns.applicationVersion", "bad version");
        assertThrows(
                IllegalArgumentException.class,
                () -> ResolverReportingConfig.from(invalidVersion, Map.of())
        );

        Properties invalidTimeouts = enabledProperties();
        invalidTimeouts.setProperty(
                "dns.reporting.connectTimeoutMillis",
                "6000"
        );
        invalidTimeouts.setProperty(
                "dns.reporting.requestTimeoutMillis",
                "5000"
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> ResolverReportingConfig.from(invalidTimeouts, Map.of())
        );
    }

    private Properties enabledProperties() {
        Properties properties = new Properties();
        properties.setProperty("dns.reporting.mode", "enabled");
        properties.setProperty(
                "dns.reporting.controlPlaneUrl",
                "https://admin.example"
        );
        properties.setProperty(
                "dns.reporting.tokenFile",
                "/run/secrets/resolver-agent-token"
        );
        return properties;
    }
}
