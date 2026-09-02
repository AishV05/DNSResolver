package com.ayushman.dns.admin;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "dns.admin.root-servers=192.0.2.10,192.0.2.11",
                "spring.datasource.url=jdbc:h2:mem:admin_status_test;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE"
        }
)
@ActiveProfiles("test")
class AdminApiApplicationTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Test
    void exposesReadOnlyPlatformStatus() {
        ResponseEntity<AdminStatusController.AdminStatusResponse> response =
                restTemplate.exchange(
                        url("/api/v1/admin/status"),
                        HttpMethod.GET,
                        AdminApiTestAuthentication.authenticated(),
                        AdminStatusController.AdminStatusResponse.class
                );

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        assertThat(response.getBody().service()).isEqualTo("dns-admin-api");
        assertThat(response.getBody().status()).isEqualTo("UP");
        assertThat(response.getBody().configuredRootServers()).isEqualTo(2);
        assertThat(response.getBody().persistedPolicyRules()).isZero();
        assertThat(response.getBody().policyEnforcement())
                .isEqualTo("PERSISTED_NOT_APPLIED");
    }

    @Test
    void exposesResolverTopologyAndActuatorHealth() {
        ResponseEntity<AdminStatusController.ResolverConfigurationResponse>
                configuration = restTemplate.exchange(
                        url("/api/v1/admin/resolver/configuration"),
                        HttpMethod.GET,
                        AdminApiTestAuthentication.authenticated(),
                        AdminStatusController.ResolverConfigurationResponse.class
                );
        ResponseEntity<HealthResponse> health = restTemplate.getForEntity(
                url("/actuator/health"),
                HealthResponse.class
        );

        assertThat(configuration.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(configuration.getBody()).isNotNull();
        assertThat(configuration.getBody().mode()).isEqualTo("recursive");
        assertThat(configuration.getBody().rootServers())
                .containsExactly("192.0.2.10", "192.0.2.11");
        assertThat(health.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(health.getBody()).isNotNull();
        assertThat(health.getBody().status()).isEqualTo("UP");
    }

    private String url(String path) {
        return "http://127.0.0.1:" + port + path;
    }

    private record HealthResponse(String status) {
    }
}
