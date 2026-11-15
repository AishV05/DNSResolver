package com.ayushman.dns.admin.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.EnumSet;

import com.ayushman.dns.admin.AdminApiTestAuthentication;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.resttestclient.TestRestTemplate;
import org.springframework.boot.resttestclient.autoconfigure.AutoConfigureTestRestTemplate;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "spring.datasource.url=jdbc:h2:mem:fleet_metrics_security_test;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE"
)
@AutoConfigureTestRestTemplate
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "dns.admin.bootstrap.username=test-bootstrap-admin",
        "dns.admin.bootstrap.token=test-bootstrap-token-at-least-thirty-two-characters"
})
class FleetMetricsSecurityTest {

    private static final String METRICS_PATH = "/api/v1/internal/fleet-metrics";

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private AdminIdentityService identityService;

    @Autowired
    private AdminUserRepository userRepository;

    @Autowired
    private AdminApiTokenRepository tokenRepository;

    @BeforeEach
    void resetIdentities() {
        tokenRepository.deleteAll();
        userRepository.deleteAll();
        identityService.bootstrapInitialAdministratorIfRequired();
    }

    @Test
    void onlyFleetMetricsReaderAndAdministratorCanScrape() {
        ResponseEntity<String> anonymous = restTemplate.getForEntity(
                url(METRICS_PATH),
                String.class
        );
        ResponseEntity<String> administrator = bearerGet(
                METRICS_PATH,
                AdminApiTestAuthentication.BOOTSTRAP_TOKEN
        );

        assertThat(anonymous.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(anonymous.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                .isEqualTo("Bearer");
        assertThat(administrator.getStatusCode()).isEqualTo(HttpStatus.OK);

        for (AdminRole role : EnumSet.of(
                AdminRole.VIEWER,
                AdminRole.POLICY_EDITOR,
                AdminRole.POLICY_SNAPSHOT_READER,
                AdminRole.RESOLVER_AGENT
        )) {
            assertThat(bearerGet(
                    METRICS_PATH,
                    createTokenFor("metrics-denied-" + role.name(), role).token()
            ).getStatusCode()).as(role.name()).isEqualTo(HttpStatus.FORBIDDEN);
        }

        IssuedAdminApiTokenResponse reader = createTokenFor(
                "fleet-metrics-reader",
                AdminRole.FLEET_METRICS_READER
        );
        ResponseEntity<String> metrics = bearerGet(METRICS_PATH, reader.token());

        assertThat(metrics.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(metrics.getHeaders().getCacheControl()).isEqualTo("no-store");
        assertThat(metrics.getHeaders().getContentType()).hasToString(
                "text/plain;version=0.0.4;charset=utf-8"
        );
        assertThat(metrics.getBody()).contains("dns_admin_fleet_policy_state");
    }

    @Test
    void fleetMetricsReaderHasNoManagementOrResolverPrivileges() {
        String token = createTokenFor(
                "isolated-fleet-metrics-reader",
                AdminRole.FLEET_METRICS_READER
        ).token();

        assertForbidden(token, "/api/v1/admin/auth/me");
        assertForbidden(token, "/api/v1/admin/fleet");
        assertForbidden(token, "/api/v1/admin/policies");
        assertForbidden(token, "/api/v1/admin/users");
        assertForbidden(token, "/api/v1/internal/policy-snapshot");
        assertThat(bearerExchange(
                HttpMethod.POST,
                "/api/v1/internal/resolver/session",
                token
        ).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(bearerExchange(
                HttpMethod.PUT,
                "/api/v1/internal/resolver/report",
                token
        ).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void revocationImmediatelyMakesTheScrapeCredentialUnusable() {
        IssuedAdminApiTokenResponse reader = createTokenFor(
                "revoked-fleet-metrics-reader",
                AdminRole.FLEET_METRICS_READER
        );
        assertThat(bearerGet(METRICS_PATH, reader.token()).getStatusCode())
                .isEqualTo(HttpStatus.OK);

        identityService.revokeToken(reader.id());

        assertThat(bearerGet(METRICS_PATH, reader.token()).getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    private IssuedAdminApiTokenResponse createTokenFor(
            String username,
            AdminRole role
    ) {
        AdminUserEntity user = userRepository.saveAndFlush(
                new AdminUserEntity(username.toLowerCase(), java.util.Set.of(role))
        );
        return identityService.issueToken(
                user.getId(),
                new IssueAdminApiTokenRequest("metrics-test", null)
        );
    }

    private void assertForbidden(String token, String path) {
        assertThat(bearerGet(path, token).getStatusCode())
                .as(path)
                .isEqualTo(HttpStatus.FORBIDDEN);
    }

    private ResponseEntity<String> bearerGet(String path, String token) {
        return bearerExchange(HttpMethod.GET, path, token);
    }

    private ResponseEntity<String> bearerExchange(
            HttpMethod method,
            String path,
            String token
    ) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        return restTemplate.exchange(
                url(path),
                method,
                new HttpEntity<>(headers),
                String.class
        );
    }

    private String url(String path) {
        return "http://127.0.0.1:" + port + path;
    }
}
