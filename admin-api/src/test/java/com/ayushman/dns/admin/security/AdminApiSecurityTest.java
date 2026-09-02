package com.ayushman.dns.admin.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.ayushman.dns.admin.AdminApiTestAuthentication;
import com.ayushman.dns.admin.policy.CreateDnsPolicyRuleRequest;
import com.ayushman.dns.admin.policy.DnsPolicyRuleResponse;
import com.ayushman.dns.policy.DnsPolicyAction;
import com.ayushman.dns.policy.DnsPolicyMatchType;
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

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "spring.datasource.url=jdbc:h2:mem:admin_security_test;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE"
)
@ActiveProfiles("test")
class AdminApiSecurityTest {

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
    void healthIsPublicButAdministrativeRoutesRequireABearerToken() {
        ResponseEntity<String> health = restTemplate.getForEntity(
                url("/actuator/health"),
                String.class
        );
        ResponseEntity<String> anonymousStatus = restTemplate.getForEntity(
                url("/api/v1/admin/status"),
                String.class
        );
        ResponseEntity<String> malformedCredentials = exchange(
                HttpMethod.GET,
                "/api/v1/admin/status",
                null,
                "Basic not-a-bearer-token",
                String.class
        );

        assertThat(health.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(health.getBody()).contains("\"status\":\"UP\"");
        assertThat(health.getBody()).doesNotContain("components");
        assertThat(anonymousStatus.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(anonymousStatus.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                .isEqualTo("Bearer");
        assertThat(malformedCredentials.getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(malformedCredentials.getHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE))
                .isEqualTo("Bearer");
        assertThat(anonymousStatus.getHeaders().getFirst(HttpHeaders.SET_COOKIE)).isNull();
        assertThat(tokenRepository.findAll()).singleElement().satisfies(token -> {
            assertThat(token.getTokenHash())
                    .isEqualTo(TokenHasher.sha256(
                            AdminApiTestAuthentication.BOOTSTRAP_TOKEN
                    ))
                    .isNotEqualTo(AdminApiTestAuthentication.BOOTSTRAP_TOKEN);
        });
    }

    @Test
    void viewerCanReadButCannotChangePoliciesOrManageIdentities() {
        String viewerToken = createTokenFor("security-viewer", AdminRole.VIEWER);

        ResponseEntity<String> readStatus = bearerExchange(
                HttpMethod.GET,
                "/api/v1/admin/status",
                null,
                viewerToken,
                String.class
        );
        ResponseEntity<String> writePolicy = bearerExchange(
                HttpMethod.POST,
                "/api/v1/admin/policies",
                new CreateDnsPolicyRuleRequest(
                        "viewer-security.example",
                        DnsPolicyMatchType.EXACT,
                        DnsPolicyAction.BLOCK
                ),
                viewerToken,
                String.class
        );
        ResponseEntity<String> listUsers = bearerExchange(
                HttpMethod.GET,
                "/api/v1/admin/users",
                null,
                viewerToken,
                String.class
        );

        assertThat(readStatus.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(writePolicy.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(listUsers.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void policyEditorCanChangePoliciesButCannotManageIdentities() {
        String editorToken = createTokenFor("security-editor", AdminRole.POLICY_EDITOR);

        ResponseEntity<DnsPolicyRuleResponse> created = bearerExchange(
                HttpMethod.POST,
                "/api/v1/admin/policies",
                new CreateDnsPolicyRuleRequest(
                        "editor-security.example",
                        DnsPolicyMatchType.EXACT,
                        DnsPolicyAction.BLOCK
                ),
                editorToken,
                DnsPolicyRuleResponse.class
        );
        ResponseEntity<String> listUsers = bearerExchange(
                HttpMethod.GET,
                "/api/v1/admin/users",
                null,
                editorToken,
                String.class
        );

        assertThat(created.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(listUsers.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
    }

    @Test
    void adminCanIssueAndImmediatelyRevokeATokenWithoutExposingItInMetadata() {
        ResponseEntity<AuthenticatedAdminResponse> me = bearerExchange(
                HttpMethod.GET,
                "/api/v1/admin/auth/me",
                null,
                AdminApiTestAuthentication.BOOTSTRAP_TOKEN,
                AuthenticatedAdminResponse.class
        );
        ResponseEntity<AdminUserResponse> createdUser = bearerExchange(
                HttpMethod.POST,
                "/api/v1/admin/users",
                new CreateAdminUserRequest("Security-Rotated-Viewer", AdminRole.VIEWER),
                AdminApiTestAuthentication.BOOTSTRAP_TOKEN,
                AdminUserResponse.class
        );

        assertThat(me.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(me.getBody()).isNotNull();
        assertThat(me.getBody().roles()).containsExactly(AdminRole.ADMIN);
        assertThat(createdUser.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(createdUser.getBody()).isNotNull();
        assertThat(createdUser.getBody().username()).isEqualTo("security-rotated-viewer");

        long userId = createdUser.getBody().id();
        ResponseEntity<IssuedAdminApiTokenResponse> issued = bearerExchange(
                HttpMethod.POST,
                "/api/v1/admin/users/" + userId + "/tokens",
                new IssueAdminApiTokenRequest("rotation-test", null),
                AdminApiTestAuthentication.BOOTSTRAP_TOKEN,
                IssuedAdminApiTokenResponse.class
        );

        assertThat(issued.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(issued.getBody()).isNotNull();
        String issuedToken = issued.getBody().token();
        assertThat(issuedToken).hasSizeGreaterThanOrEqualTo(32);

        ResponseEntity<String> tokenMetadata = bearerExchange(
                HttpMethod.GET,
                "/api/v1/admin/users/" + userId + "/tokens",
                null,
                AdminApiTestAuthentication.BOOTSTRAP_TOKEN,
                String.class
        );
        ResponseEntity<String> issuedTokenAccess = bearerExchange(
                HttpMethod.GET,
                "/api/v1/admin/status",
                null,
                issuedToken,
                String.class
        );
        ResponseEntity<AdminApiTokenResponse[]> usedTokenMetadata = bearerExchange(
                HttpMethod.GET,
                "/api/v1/admin/users/" + userId + "/tokens",
                null,
                AdminApiTestAuthentication.BOOTSTRAP_TOKEN,
                AdminApiTokenResponse[].class
        );
        ResponseEntity<Void> revocation = bearerExchange(
                HttpMethod.DELETE,
                "/api/v1/admin/tokens/" + issued.getBody().id(),
                null,
                AdminApiTestAuthentication.BOOTSTRAP_TOKEN,
                Void.class
        );
        ResponseEntity<String> revokedTokenAccess = bearerExchange(
                HttpMethod.GET,
                "/api/v1/admin/status",
                null,
                issuedToken,
                String.class
        );
        ResponseEntity<String> actuatorInfo = bearerExchange(
                HttpMethod.GET,
                "/actuator/info",
                null,
                AdminApiTestAuthentication.BOOTSTRAP_TOKEN,
                String.class
        );

        assertThat(tokenMetadata.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(tokenMetadata.getBody()).doesNotContain(issuedToken);
        assertThat(tokenMetadata.getBody()).doesNotContain("tokenHash");
        assertThat(issuedTokenAccess.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(usedTokenMetadata.getBody()).singleElement().satisfies(token ->
                assertThat(token.lastUsedAt()).isNotNull()
        );
        assertThat(revocation.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(revokedTokenAccess.getStatusCode())
                .isEqualTo(HttpStatus.UNAUTHORIZED);
        assertThat(actuatorInfo.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
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

    private <T> ResponseEntity<T> bearerExchange(
            HttpMethod method,
            String path,
            Object body,
            String token,
            Class<T> responseType
    ) {
        return exchange(
                method,
                path,
                body,
                "Bearer " + token,
                responseType
        );
    }

    private <T> ResponseEntity<T> exchange(
            HttpMethod method,
            String path,
            Object body,
            String authorization,
            Class<T> responseType
    ) {
        HttpHeaders headers = new HttpHeaders();
        headers.set(HttpHeaders.AUTHORIZATION, authorization);
        return restTemplate.exchange(
                url(path),
                method,
                new HttpEntity<>(body, headers),
                responseType
        );
    }

    private String url(String path) {
        return "http://127.0.0.1:" + port + path;
    }
}
