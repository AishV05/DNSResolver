package com.ayushman.dns.admin.fleet;

import static org.assertj.core.api.Assertions.assertThat;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import com.ayushman.dns.admin.AdminApiTestAuthentication;
import com.ayushman.dns.admin.AdminStatusController.AdminStatusResponse;
import com.ayushman.dns.admin.policy.CreateDnsPolicyRuleRequest;
import com.ayushman.dns.admin.policy.DnsPolicyRuleResponse;
import com.ayushman.dns.admin.security.AdminIdentityService;
import com.ayushman.dns.admin.security.AdminRole;
import com.ayushman.dns.admin.security.AdminUserResponse;
import com.ayushman.dns.admin.security.CreateAdminUserRequest;
import com.ayushman.dns.admin.security.IssueAdminApiTokenRequest;
import com.ayushman.dns.admin.security.IssuedAdminApiTokenResponse;
import com.ayushman.dns.fleet.ResolverFleetPolicyState;
import com.ayushman.dns.fleet.ResolverPolicyMode;
import com.ayushman.dns.fleet.ResolverPolicySyncState;
import com.ayushman.dns.fleet.ResolverRuntimeReport;
import com.ayushman.dns.fleet.ResolverSessionLease;
import com.ayushman.dns.fleet.ResolverSessionStart;
import com.ayushman.dns.policy.DnsPolicyAction;
import com.ayushman.dns.policy.DnsPolicyMatchType;
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
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "spring.datasource.url=jdbc:h2:mem:resolver_fleet_api_test;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE"
)
@AutoConfigureTestRestTemplate
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "dns.admin.bootstrap.username=test-bootstrap-admin",
        "dns.admin.bootstrap.token=test-bootstrap-token-at-least-thirty-two-characters",
        "dns.admin.fleet.report-freshness-millis=1000"
})
class ResolverFleetApiTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private AdminIdentityService identityService;

    @Autowired
    private ResolverSessionRepository sessionRepository;

    @BeforeEach
    void resetDatabase() {
        jdbcTemplate.update("UPDATE resolver_instances SET active_session_id = NULL");
        jdbcTemplate.update("DELETE FROM resolver_sessions");
        jdbcTemplate.update("DELETE FROM resolver_boot_fences");
        jdbcTemplate.update("DELETE FROM resolver_instances");
        jdbcTemplate.update("DELETE FROM admin_api_tokens");
        jdbcTemplate.update("DELETE FROM admin_user_roles");
        jdbcTemplate.update("DELETE FROM admin_users");
        jdbcTemplate.update("DELETE FROM dns_policy_rules");
        jdbcTemplate.update("""
                UPDATE dns_policy_snapshot_state
                SET revision = 0, published_at = CURRENT_TIMESTAMP
                WHERE singleton_id = 1
                """);
        identityService.bootstrapInitialAdministratorIfRequired();
    }

    @Test
    void fleetStatusTracksMembershipFreshnessAndPolicyPublication() {
        RegisteredResolverResponse registered = requireRegistrationBody(
                register("resolver-status-01")
        );
        String resolverToken = registered.credential().token();

        ResponseEntity<ResolverFleetStatusResponse> registeredStatus = fleet();
        assertThat(registeredStatus.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(registeredStatus.getHeaders().getCacheControl())
                .contains("no-store");
        assertThat(registeredStatus.getBody()).isNotNull();
        assertThat(registeredStatus.getBody().policyEnforcement()).isEqualTo(
                ResolverFleetPolicyState.DATA_PLANE_NOT_CONVERGED
        );
        assertThat(registeredStatus.getBody().resolvers()).singleElement()
                .extracting(ResolverFleetMemberStatusResponse::state)
                .isEqualTo(ResolverFleetMemberState.NO_ACTIVE_SESSION);

        ResolverSessionStart sessionStart = new ResolverSessionStart(
                UUID.randomUUID(),
                "0.1.0-SNAPSHOT"
        );
        ResolverSessionLease lease = requireLease(start(
                resolverToken,
                sessionStart
        ));
        assertThat(fleet().getBody().resolvers()).singleElement()
                .extracting(ResolverFleetMemberStatusResponse::state)
                .isEqualTo(ResolverFleetMemberState.NO_REPORT);

        assertThat(report(
                resolverToken,
                healthyReport(lease, 1, 0, 0)
        ).getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        ResolverFleetStatusResponse converged = requireFleetBody(fleet());
        assertThat(converged.policyEnforcement()).isEqualTo(
                ResolverFleetPolicyState.DATA_PLANE_CONVERGED
        );
        assertThat(converged.expectedResolverCount()).isEqualTo(1);
        assertThat(converged.freshResolverCount()).isEqualTo(1);
        assertThat(converged.convergedResolverCount()).isEqualTo(1);

        ResponseEntity<DnsPolicyRuleResponse> policy = adminExchange(
                HttpMethod.POST,
                "/api/v1/admin/policies",
                new CreateDnsPolicyRuleRequest(
                        "blocked-status.example",
                        DnsPolicyMatchType.EXACT,
                        DnsPolicyAction.BLOCK
                ),
                DnsPolicyRuleResponse.class
        );
        assertThat(policy.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        ResolverFleetStatusResponse revisionMismatch = requireFleetBody(fleet());
        assertThat(revisionMismatch.publishedPolicyRevision()).isEqualTo(1);
        assertThat(revisionMismatch.publishedPolicyRuleCount()).isEqualTo(1);
        assertThat(revisionMismatch.policyEnforcement()).isEqualTo(
                ResolverFleetPolicyState.DATA_PLANE_NOT_CONVERGED
        );
        assertThat(revisionMismatch.resolvers()).singleElement()
                .extracting(ResolverFleetMemberStatusResponse::state)
                .isEqualTo(ResolverFleetMemberState.REVISION_MISMATCH);

        assertThat(report(
                resolverToken,
                healthyReport(lease, 2, 1, 1)
        ).getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(requireFleetBody(fleet()).policyEnforcement()).isEqualTo(
                ResolverFleetPolicyState.DATA_PLANE_CONVERGED
        );

        jdbcTemplate.update(
                "UPDATE resolver_sessions SET last_report_received_at = ? "
                        + "WHERE session_id = ?",
                Timestamp.from(Instant.now().minusSeconds(10)),
                lease.sessionId().toString()
        );
        ResolverFleetStatusResponse stale = requireFleetBody(fleet());
        assertThat(stale.policyEnforcement()).isEqualTo(
                ResolverFleetPolicyState.DATA_PLANE_NOT_CONVERGED
        );
        assertThat(stale.freshResolverCount()).isZero();
        assertThat(stale.resolvers()).singleElement()
                .extracting(ResolverFleetMemberStatusResponse::state)
                .isEqualTo(ResolverFleetMemberState.REPORT_STALE);

        ResponseEntity<AdminStatusResponse> adminStatus = adminExchange(
                HttpMethod.GET,
                "/api/v1/admin/status",
                null,
                AdminStatusResponse.class
        );
        assertThat(adminStatus.getBody()).isNotNull();
        assertThat(adminStatus.getBody().policyEnforcement()).isEqualTo(
                ResolverFleetPolicyState.DATA_PLANE_NOT_CONVERGED
        );

        ResponseEntity<ResolverRegistrationResponse> disabled = adminExchange(
                HttpMethod.PUT,
                "/api/v1/admin/resolvers/resolver-status-01",
                new UpdateResolverRegistrationRequest(false),
                ResolverRegistrationResponse.class
        );
        assertThat(disabled.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(disabled.getBody()).isNotNull();
        assertThat(disabled.getBody().enabled()).isFalse();
        ResolverFleetStatusResponse excluded = requireFleetBody(fleet());
        assertThat(excluded.policyEnforcement()).isEqualTo(
                ResolverFleetPolicyState.DATA_PLANE_UNOBSERVED
        );
        assertThat(excluded.expectedResolverCount()).isZero();
        assertThat(excluded.resolvers()).singleElement()
                .extracting(ResolverFleetMemberStatusResponse::state)
                .isEqualTo(ResolverFleetMemberState.EXCLUDED_DISABLED);
        assertThat(bearerExchange(
                HttpMethod.GET,
                "/api/v1/internal/policy-snapshot",
                null,
                resolverToken,
                String.class
        ).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);

        ResponseEntity<ResolverRegistrationResponse> enabled = adminExchange(
                HttpMethod.PUT,
                "/api/v1/admin/resolvers/resolver-status-01",
                new UpdateResolverRegistrationRequest(true),
                ResolverRegistrationResponse.class
        );
        assertThat(enabled.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(enabled.getBody()).isNotNull();
        assertThat(enabled.getBody().enabled()).isTrue();
        assertThat(requireFleetBody(fleet()).resolvers()).singleElement()
                .extracting(ResolverFleetMemberStatusResponse::state)
                .isEqualTo(ResolverFleetMemberState.NO_ACTIVE_SESSION);
        assertThat(bearerExchange(
                HttpMethod.POST,
                "/api/v1/internal/resolver/session",
                sessionStart,
                resolverToken,
                String.class
        ).getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        ResolverSessionLease replacement = requireLease(start(
                resolverToken,
                new ResolverSessionStart(UUID.randomUUID(), "0.1.0-SNAPSHOT")
        ));
        assertThat(replacement.sessionGeneration()).isEqualTo(2);
    }

    @Test
    void fleetReadAndMembershipMutationUseManagementRolesOnly() {
        RegisteredResolverResponse registered = requireRegistrationBody(
                register("resolver-auth-01")
        );
        String resolverToken = registered.credential().token();
        String viewerToken = createManagementToken(
                "fleet-status-viewer",
                AdminRole.VIEWER
        );

        assertThat(bearerExchange(
                HttpMethod.GET,
                "/api/v1/admin/fleet",
                null,
                viewerToken,
                String.class
        ).getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(bearerExchange(
                HttpMethod.PUT,
                "/api/v1/admin/resolvers/resolver-auth-01",
                new UpdateResolverRegistrationRequest(false),
                viewerToken,
                String.class
        ).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(bearerExchange(
                HttpMethod.GET,
                "/api/v1/admin/fleet",
                null,
                resolverToken,
                String.class
        ).getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(restTemplate.getForEntity(
                url("/api/v1/admin/fleet"),
                String.class
        ).getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED);
    }

    @Test
    void registrationIssuesOneHashOnlyCredentialWithResolverOnlyPrivileges() {
        ResponseEntity<RegisteredResolverResponse> registration = register(
                "resolver-india-01"
        );

        assertThat(registration.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(registration.getHeaders().getCacheControl())
                .contains("no-store");
        assertThat(registration.getHeaders().getLocation())
                .hasPath("/api/v1/admin/resolvers/resolver-india-01");
        RegisteredResolverResponse body = registration.getBody();
        assertThat(body).isNotNull();
        assertThat(body.resolver().resolverId()).isEqualTo("resolver-india-01");
        assertThat(body.credential().token()).hasSizeGreaterThanOrEqualTo(32);

        String rawToken = body.credential().token();
        Map<String, Object> storedToken = jdbcTemplate.queryForMap(
                "SELECT token_hash, token_label FROM admin_api_tokens WHERE id = ?",
                body.credential().id()
        );
        assertThat(storedToken.get("token_hash").toString())
                .hasSize(64)
                .isNotEqualTo(rawToken);
        assertThat(storedToken.get("token_label")).isEqualTo("resolver-agent");

        ResponseEntity<String> snapshot = bearerExchange(
                HttpMethod.GET,
                "/api/v1/internal/policy-snapshot",
                null,
                rawToken,
                String.class
        );
        ResponseEntity<String> adminStatus = bearerExchange(
                HttpMethod.GET,
                "/api/v1/admin/status",
                null,
                rawToken,
                String.class
        );
        ResponseEntity<String> authMe = bearerExchange(
                HttpMethod.GET,
                "/api/v1/admin/auth/me",
                null,
                rawToken,
                String.class
        );
        ResponseEntity<String> adminSession = adminExchange(
                HttpMethod.POST,
                "/api/v1/internal/resolver/session",
                new ResolverSessionStart(UUID.randomUUID(), "0.1.0"),
                String.class
        );
        ResponseEntity<String> list = adminExchange(
                HttpMethod.GET,
                "/api/v1/admin/resolvers",
                null,
                String.class
        );
        ResponseEntity<String> unboundAgent = adminExchange(
                HttpMethod.POST,
                "/api/v1/admin/users",
                new CreateAdminUserRequest("unbound-resolver", AdminRole.RESOLVER_AGENT),
                String.class
        );

        assertThat(snapshot.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(adminStatus.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(authMe.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(adminSession.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(list.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(list.getBody()).doesNotContain(rawToken).doesNotContain("tokenHash");
        assertThat(unboundAgent.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void sessionsFenceOldBootsAndReportsAreOrderedAndIdempotent() {
        String token = requireRegistrationBody(register("resolver-session-01"))
                .credential().token();
        UUID firstBoot = UUID.randomUUID();
        ResolverSessionStart firstStart = new ResolverSessionStart(
                firstBoot,
                "0.1.0-SNAPSHOT"
        );

        ResponseEntity<ResolverSessionLease> created = start(token, firstStart);
        ResponseEntity<ResolverSessionLease> retried = start(token, firstStart);
        ResponseEntity<String> versionConflict = bearerExchange(
                HttpMethod.POST,
                "/api/v1/internal/resolver/session",
                new ResolverSessionStart(firstBoot, "0.1.1"),
                token,
                String.class
        );

        assertThat(created.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(retried.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(retried.getBody()).isEqualTo(created.getBody());
        assertThat(versionConflict.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);

        ResolverSessionLease lease = created.getBody();
        assertThat(lease).isNotNull();
        ResolverRuntimeReport firstReport = healthyReport(lease, 1, 7, 3);
        assertThat(report(token, firstReport).getStatusCode())
                .isEqualTo(HttpStatus.NO_CONTENT);
        ResolverSessionEntity stored = sessionRepository.findById(
                lease.sessionId().toString()
        ).orElseThrow();
        Instant firstReceipt = stored.getLastReportReceivedAt();
        long firstEntityVersion = stored.getVersion();

        assertThat(report(token, firstReport).getStatusCode())
                .isEqualTo(HttpStatus.NO_CONTENT);
        ResolverSessionEntity afterRetry = sessionRepository.findById(
                lease.sessionId().toString()
        ).orElseThrow();
        assertThat(afterRetry.getLastReportReceivedAt()).isEqualTo(firstReceipt);
        assertThat(afterRetry.getVersion()).isEqualTo(firstEntityVersion);

        ResolverRuntimeReport changedSameSequence = healthyReport(lease, 1, 8, 4);
        assertThat(report(token, changedSameSequence).getStatusCode())
                .isEqualTo(HttpStatus.CONFLICT);
        assertThat(report(token, healthyReport(lease, 3, 8, 4)).getStatusCode())
                .isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(report(token, healthyReport(lease, 2, 8, 4)).getStatusCode())
                .isEqualTo(HttpStatus.CONFLICT);

        ResponseEntity<ResolverSessionLease> second = start(
                token,
                new ResolverSessionStart(UUID.randomUUID(), "0.1.0-SNAPSHOT")
        );
        assertThat(second.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(second.getBody()).isNotNull();
        assertThat(second.getBody().sessionGeneration()).isEqualTo(2);
        assertThat(report(token, healthyReport(lease, 4, 9, 5)).getStatusCode())
                .isEqualTo(HttpStatus.CONFLICT);
        assertThat(bearerExchange(
                HttpMethod.POST,
                "/api/v1/internal/resolver/session",
                firstStart,
                token,
                String.class
        ).getStatusCode())
                .isEqualTo(HttpStatus.CONFLICT);
    }

    @Test
    void authenticatedPrincipalSelectsResolverAndStrictJsonRejectsExtraFields() {
        RegisteredResolverResponse first = requireRegistrationBody(
                register("resolver-a")
        );
        RegisteredResolverResponse second = requireRegistrationBody(
                register("resolver-b")
        );
        String token = first.credential().token();
        UUID bootId = UUID.randomUUID();

        ResponseEntity<ResolverSessionLease> lease = start(
                token,
                new ResolverSessionStart(bootId, "0.1.0")
        );
        assertThat(lease.getBody()).isNotNull();
        assertThat(lease.getBody().resolverId()).isEqualTo("resolver-a");
        assertThat(report(
                second.credential().token(),
                healthyReport(lease.getBody(), 1, 0, 0)
        ).getStatusCode()).isEqualTo(HttpStatus.CONFLICT);

        String unknownField = """
                {"schemaVersion":1,"bootId":"%s","applicationVersion":"0.1.0","resolverId":"resolver-b"}
                """.formatted(UUID.randomUUID()).trim();
        String duplicateField = """
                {"schemaVersion":1,"bootId":"%s","bootId":"%s","applicationVersion":"0.1.0"}
                """.formatted(UUID.randomUUID(), UUID.randomUUID()).trim();
        String missingField = """
                {"schemaVersion":1,"applicationVersion":"0.1.0"}
                """.trim();
        String nullPrimitive = """
                {"schemaVersion":null,"bootId":"%s","applicationVersion":"0.1.0"}
                """.formatted(UUID.randomUUID()).trim();
        String trailingJson = """
                {"schemaVersion":1,"bootId":"%s","applicationVersion":"0.1.0"} {}
                """.formatted(UUID.randomUUID()).trim();

        assertThat(rawJson(token, unknownField).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(rawJson(token, duplicateField).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(rawJson(token, missingField).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(rawJson(token, nullPrimitive).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(rawJson(token, trailingJson).getStatusCode())
                .isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void duplicateAndInvalidRegistrationsAreRejected() {
        assertThat(register("valid-resolver").getStatusCode())
                .isEqualTo(HttpStatus.CREATED);
        ResponseEntity<String> duplicate = adminExchange(
                HttpMethod.POST,
                "/api/v1/admin/resolvers",
                new RegisterResolverRequest("valid-resolver", null),
                String.class
        );
        assertThat(duplicate.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        ResponseEntity<String> invalid = adminExchange(
                HttpMethod.POST,
                "/api/v1/admin/resolvers",
                new RegisterResolverRequest("Invalid Resolver", null),
                String.class
        );
        assertThat(invalid.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
    }

    @Test
    void concurrentSessionRetriesProduceOneDurableLease() throws Exception {
        String token = requireRegistrationBody(register("resolver-concurrent"))
                .credential().token();
        ResolverSessionStart start = new ResolverSessionStart(
                UUID.randomUUID(),
                "0.1.0"
        );
        CountDownLatch ready = new CountDownLatch(2);
        CountDownLatch release = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Future<ResponseEntity<ResolverSessionLease>> first = executor.submit(
                    () -> concurrentStart(token, start, ready, release)
            );
            Future<ResponseEntity<ResolverSessionLease>> second = executor.submit(
                    () -> concurrentStart(token, start, ready, release)
            );
            ready.await();
            release.countDown();

            ResponseEntity<ResolverSessionLease> firstResponse = first.get();
            ResponseEntity<ResolverSessionLease> secondResponse = second.get();
            assertThat(firstResponse.getStatusCode()).isIn(
                    HttpStatus.CREATED,
                    HttpStatus.OK
            );
            assertThat(secondResponse.getStatusCode()).isIn(
                    HttpStatus.CREATED,
                    HttpStatus.OK
            );
            assertThat(firstResponse.getStatusCode())
                    .isNotEqualTo(secondResponse.getStatusCode());
            assertThat(firstResponse.getBody()).isEqualTo(secondResponse.getBody());
            assertThat(sessionRepository.count()).isEqualTo(1);
            assertThat(firstResponse.getBody()).isNotNull();
            assertThat(firstResponse.getBody().sessionGeneration()).isEqualTo(1);
        } finally {
            release.countDown();
            executor.shutdownNow();
        }
    }

    @Test
    void sessionGenerationNeverWraps() {
        String token = requireRegistrationBody(register("resolver-overflow"))
                .credential().token();
        jdbcTemplate.update(
                "UPDATE resolver_instances SET last_session_generation = ? WHERE resolver_id = ?",
                Long.MAX_VALUE,
                "resolver-overflow"
        );

        ResponseEntity<String> response = bearerExchange(
                HttpMethod.POST,
                "/api/v1/internal/resolver/session",
                new ResolverSessionStart(UUID.randomUUID(), "0.1.0"),
                token,
                String.class
        );
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(sessionRepository.count()).isZero();
    }

    private RegisteredResolverResponse requireRegistrationBody(
            ResponseEntity<RegisteredResolverResponse> response
    ) {
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(response.getBody()).isNotNull();
        return response.getBody();
    }

    private ResolverSessionLease requireLease(
            ResponseEntity<ResolverSessionLease> response
    ) {
        assertThat(response.getStatusCode()).isIn(HttpStatus.CREATED, HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        return response.getBody();
    }

    private ResolverFleetStatusResponse requireFleetBody(
            ResponseEntity<ResolverFleetStatusResponse> response
    ) {
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody()).isNotNull();
        return response.getBody();
    }

    private ResponseEntity<ResolverFleetStatusResponse> fleet() {
        return adminExchange(
                HttpMethod.GET,
                "/api/v1/admin/fleet",
                null,
                ResolverFleetStatusResponse.class
        );
    }

    private String createManagementToken(String username, AdminRole role) {
        ResponseEntity<AdminUserResponse> user = adminExchange(
                HttpMethod.POST,
                "/api/v1/admin/users",
                new CreateAdminUserRequest(username, role),
                AdminUserResponse.class
        );
        assertThat(user.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(user.getBody()).isNotNull();
        ResponseEntity<IssuedAdminApiTokenResponse> token = adminExchange(
                HttpMethod.POST,
                "/api/v1/admin/users/" + user.getBody().id() + "/tokens",
                new IssueAdminApiTokenRequest("fleet-status-test", null),
                IssuedAdminApiTokenResponse.class
        );
        assertThat(token.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(token.getBody()).isNotNull();
        return token.getBody().token();
    }

    private ResponseEntity<RegisteredResolverResponse> register(String resolverId) {
        return adminExchange(
                HttpMethod.POST,
                "/api/v1/admin/resolvers",
                new RegisterResolverRequest(resolverId, null),
                RegisteredResolverResponse.class
        );
    }

    private ResponseEntity<ResolverSessionLease> start(
            String token,
            ResolverSessionStart request
    ) {
        return bearerExchange(
                HttpMethod.POST,
                "/api/v1/internal/resolver/session",
                request,
                token,
                ResolverSessionLease.class
        );
    }

    private ResponseEntity<ResolverSessionLease> concurrentStart(
            String token,
            ResolverSessionStart request,
            CountDownLatch ready,
            CountDownLatch release
    ) throws InterruptedException {
        ready.countDown();
        release.await();
        return start(token, request);
    }

    private ResponseEntity<Void> report(
            String token,
            ResolverRuntimeReport report
    ) {
        return bearerExchange(
                HttpMethod.PUT,
                "/api/v1/internal/resolver/report",
                report,
                token,
                Void.class
        );
    }

    private ResolverRuntimeReport healthyReport(
            ResolverSessionLease lease,
            long sequence,
            long revision,
            int ruleCount
    ) {
        return new ResolverRuntimeReport(
                lease.sessionId(),
                lease.bootId(),
                lease.sessionGeneration(),
                sequence,
                "0.1.0-SNAPSHOT",
                ResolverPolicyMode.REQUIRED,
                true,
                revision,
                ruleCount,
                true,
                ResolverPolicySyncState.HEALTHY
        );
    }

    private ResponseEntity<String> rawJson(String token, String json) {
        HttpHeaders headers = bearerHeaders(token);
        headers.setContentType(MediaType.APPLICATION_JSON);
        return restTemplate.exchange(
                url("/api/v1/internal/resolver/session"),
                HttpMethod.POST,
                new HttpEntity<>(json, headers),
                String.class
        );
    }

    private <T> ResponseEntity<T> adminExchange(
            HttpMethod method,
            String path,
            Object body,
            Class<T> responseType
    ) {
        return bearerExchange(
                method,
                path,
                body,
                AdminApiTestAuthentication.BOOTSTRAP_TOKEN,
                responseType
        );
    }

    private <T> ResponseEntity<T> bearerExchange(
            HttpMethod method,
            String path,
            Object body,
            String token,
            Class<T> responseType
    ) {
        HttpHeaders headers = bearerHeaders(token);
        return restTemplate.exchange(
                url(path),
                method,
                new HttpEntity<>(body, headers),
                responseType
        );
    }

    private HttpHeaders bearerHeaders(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(token);
        return headers;
    }

    private String url(String path) {
        return "http://127.0.0.1:" + port + path;
    }
}
