package com.ayushman.dns.admin.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
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
        properties = "spring.datasource.url=jdbc:h2:mem:policy_snapshot_security_test;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE"
)
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "dns.admin.bootstrap.username=test-bootstrap-admin",
        "dns.admin.bootstrap.token=test-bootstrap-token-at-least-thirty-two-characters"
})
class PolicySnapshotSecurityTest {

    private static final String SNAPSHOT_PATH =
            "/api/v1/internal/policy-snapshot";

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
    void policySnapshotReaderCanReadTheSnapshotButNoAdminEndpoint() {
        String readerToken = createTokenFor(
                "policy-snapshot-reader",
                AdminRole.POLICY_SNAPSHOT_READER
        );

        assertThat(bearerExchange(
                HttpMethod.GET,
                SNAPSHOT_PATH,
                readerToken
        ).getStatusCode()).isEqualTo(HttpStatus.OK);

        List<SecuredRequest> adminRequests = List.of(
                new SecuredRequest(HttpMethod.GET, "/api/v1/admin/auth/me"),
                new SecuredRequest(HttpMethod.GET, "/api/v1/admin/status"),
                new SecuredRequest(
                        HttpMethod.GET,
                        "/api/v1/admin/resolver/configuration"
                ),
                new SecuredRequest(HttpMethod.GET, "/api/v1/admin/policies"),
                new SecuredRequest(HttpMethod.GET, "/api/v1/admin/policies/1"),
                new SecuredRequest(HttpMethod.POST, "/api/v1/admin/policies"),
                new SecuredRequest(HttpMethod.PUT, "/api/v1/admin/policies/1"),
                new SecuredRequest(HttpMethod.DELETE, "/api/v1/admin/policies/1"),
                new SecuredRequest(HttpMethod.GET, "/api/v1/admin/users"),
                new SecuredRequest(HttpMethod.GET, "/api/v1/admin/users/1/tokens"),
                new SecuredRequest(HttpMethod.POST, "/api/v1/admin/users"),
                new SecuredRequest(HttpMethod.POST, "/api/v1/admin/users/1/tokens"),
                new SecuredRequest(HttpMethod.DELETE, "/api/v1/admin/tokens/1")
        );

        for (SecuredRequest request : adminRequests) {
            assertThat(bearerExchange(
                    request.method(),
                    request.path(),
                    readerToken
            ).getStatusCode())
                    .as("%s %s", request.method(), request.path())
                    .isEqualTo(HttpStatus.FORBIDDEN);
        }

        assertThat(bearerExchange(
                HttpMethod.POST,
                SNAPSHOT_PATH,
                readerToken
        ).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void snapshotRequiresAnExplicitlyAuthorizedRole() {
        String viewerToken = createTokenFor("snapshot-security-viewer", AdminRole.VIEWER);
        String editorToken = createTokenFor(
                "snapshot-security-editor",
                AdminRole.POLICY_EDITOR
        );

        assertThat(restTemplate.getForEntity(
                url(SNAPSHOT_PATH),
                String.class
        ).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(bearerExchange(
                HttpMethod.GET,
                SNAPSHOT_PATH,
                viewerToken
        ).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(bearerExchange(
                HttpMethod.GET,
                SNAPSHOT_PATH,
                editorToken
        ).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(bearerExchange(
                HttpMethod.GET,
                SNAPSHOT_PATH,
                com.ayushman.dns.admin.AdminApiTestAuthentication.BOOTSTRAP_TOKEN
        ).getStatusCode()).isEqualTo(HttpStatus.OK);
    }

    private String createTokenFor(String username, AdminRole role) {
        AdminUserResponse user = identityService.createUser(
                new CreateAdminUserRequest(username, role)
        );
        return identityService.issueToken(
                user.id(),
                new IssueAdminApiTokenRequest("test-token", null)
        ).token();
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
                new HttpEntity<>(null, headers),
                String.class
        );
    }

    private String url(String path) {
        return "http://127.0.0.1:" + port + path;
    }

    private record SecuredRequest(HttpMethod method, String path) {
    }
}
