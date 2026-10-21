package com.ayushman.dns.admin.policy;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.List;

import com.ayushman.dns.admin.AdminApiTestAuthentication;
import com.ayushman.dns.policy.DnsPolicyAction;
import com.ayushman.dns.policy.DnsPolicyMatchType;
import com.ayushman.dns.policy.DnsPolicyRule;
import com.ayushman.dns.policy.DnsPolicySnapshot;
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
        properties = "spring.datasource.url=jdbc:h2:mem:dns_policy_snapshot_api_test;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE"
)
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "dns.admin.bootstrap.username=test-bootstrap-admin",
        "dns.admin.bootstrap.token=test-bootstrap-token-at-least-thirty-two-characters"
})
class DnsPolicySnapshotApiTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private DnsPolicyRuleRepository ruleRepository;

    @Autowired
    private DnsPolicyRuleService ruleService;

    @Autowired
    private DnsPolicySnapshotService snapshotService;

    @BeforeEach
    void clearPolicyRows() {
        ruleRepository.deleteAll();
    }

    @Test
    void servesAStableConditionalRepresentationForOneRevision() {
        DnsPolicySnapshot before = snapshotService.currentSnapshot();

        ResponseEntity<String> first = getSnapshot(null);
        ResponseEntity<String> second = getSnapshot(null);

        assertThat(first.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(first.getHeaders().getETag())
                .isEqualTo(etag(before.revision()));
        assertThat(first.getHeaders().getCacheControl())
                .contains("no-cache")
                .contains("private");
        assertThat(first.getBody()).isEqualTo(second.getBody());
        assertThat(second.getHeaders().getETag())
                .isEqualTo(first.getHeaders().getETag());

        ResponseEntity<String> notModified = getSnapshot(
                first.getHeaders().getETag()
        );
        assertThat(notModified.getStatusCode())
                .isEqualTo(HttpStatus.NOT_MODIFIED);
        assertThat(notModified.getBody()).isNull();
        assertThat(notModified.getHeaders().getETag())
                .isEqualTo(first.getHeaders().getETag());

        ResponseEntity<String> weakMatch = getSnapshot(
                "W/" + first.getHeaders().getETag()
        );
        assertThat(weakMatch.getStatusCode())
                .isEqualTo(HttpStatus.NOT_MODIFIED);
    }

    @Test
    void publishesOneNewRevisionPerSuccessfulMutation() {
        DnsPolicySnapshot initial = snapshotService.currentSnapshot();
        Instant initialPublishedAt = initial.publishedAt();

        DnsPolicyRuleResponse zeta = ruleService.create(createRequest(
                "z.example",
                DnsPolicyMatchType.EXACT
        ));
        ruleService.create(createRequest(
                "A.Example.",
                DnsPolicyMatchType.EXACT
        ));
        DnsPolicyRuleResponse suffix = ruleService.create(createRequest(
                "a.example",
                DnsPolicyMatchType.DOMAIN_AND_SUBDOMAINS
        ));

        DnsPolicySnapshot created = snapshotService.currentSnapshot();
        assertThat(created.schemaVersion())
                .isEqualTo(DnsPolicySnapshot.CURRENT_SCHEMA_VERSION);
        assertThat(created.revision()).isEqualTo(initial.revision() + 3);
        assertThat(created.publishedAt()).isAfterOrEqualTo(initialPublishedAt);
        assertThat(created.rules()).containsExactly(
                new DnsPolicyRule(
                        "a.example",
                        DnsPolicyMatchType.DOMAIN_AND_SUBDOMAINS,
                        DnsPolicyAction.BLOCK
                ),
                new DnsPolicyRule(
                        "a.example",
                        DnsPolicyMatchType.EXACT,
                        DnsPolicyAction.BLOCK
                ),
                new DnsPolicyRule(
                        "z.example",
                        DnsPolicyMatchType.EXACT,
                        DnsPolicyAction.BLOCK
                )
        );

        ruleService.update(
                suffix.id(),
                new UpdateDnsPolicyRuleRequest(
                        suffix.domainName(),
                        suffix.matchType(),
                        suffix.action(),
                        false
                )
        );
        DnsPolicySnapshot disabled = snapshotService.currentSnapshot();
        assertThat(disabled.revision()).isEqualTo(created.revision() + 1);
        assertThat(disabled.rules())
                .extracting(DnsPolicyRule::matchType)
                .doesNotContain(DnsPolicyMatchType.DOMAIN_AND_SUBDOMAINS);

        ruleService.delete(zeta.id());
        DnsPolicySnapshot deleted = snapshotService.currentSnapshot();
        assertThat(deleted.revision()).isEqualTo(disabled.revision() + 1);
        assertThat(deleted.rules())
                .extracting(DnsPolicyRule::domainName)
                .containsExactly("a.example");

        DnsPolicySnapshotService.DnsPolicyPublicationStatus status =
                snapshotService.currentPublicationStatus();
        assertThat(status.revision()).isEqualTo(deleted.revision());
        assertThat(status.persistedRuleCount()).isEqualTo(2);
        assertThat(status.enabledRuleCount()).isEqualTo(1);
    }

    @Test
    void failedMutationDoesNotPublishAPartialRevision() {
        CreateDnsPolicyRuleRequest request = createRequest(
                "duplicate.example",
                DnsPolicyMatchType.EXACT
        );
        DnsPolicyRuleResponse existing = ruleService.create(request);
        DnsPolicySnapshot beforeFailure = snapshotService.currentSnapshot();

        assertThatThrownBy(() -> ruleService.create(request))
                .isInstanceOf(DuplicateDnsPolicyRuleException.class);

        assertThatThrownBy(() -> ruleService.update(
                999_999L,
                new UpdateDnsPolicyRuleRequest(
                        "missing.example",
                        DnsPolicyMatchType.EXACT,
                        DnsPolicyAction.BLOCK,
                        true
                )
        )).isInstanceOf(DnsPolicyRuleNotFoundException.class);

        assertThatThrownBy(() -> ruleService.delete(999_999L))
                .isInstanceOf(DnsPolicyRuleNotFoundException.class);

        assertThatThrownBy(() -> ruleService.update(
                existing.id(),
                new UpdateDnsPolicyRuleRequest(
                        "invalid..example",
                        DnsPolicyMatchType.EXACT,
                        DnsPolicyAction.BLOCK,
                        true
                )
        )).isInstanceOf(IllegalArgumentException.class);

        DnsPolicySnapshot afterFailure = snapshotService.currentSnapshot();
        assertThat(afterFailure).isEqualTo(beforeFailure);
        assertThat(afterFailure.rules()).hasSize(1);
    }

    private CreateDnsPolicyRuleRequest createRequest(
            String domainName,
            DnsPolicyMatchType matchType
    ) {
        return new CreateDnsPolicyRuleRequest(
                domainName,
                matchType,
                DnsPolicyAction.BLOCK
        );
    }

    private ResponseEntity<String> getSnapshot(String ifNoneMatch) {
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(AdminApiTestAuthentication.BOOTSTRAP_TOKEN);
        if (ifNoneMatch != null) {
            headers.setIfNoneMatch(List.of(ifNoneMatch));
        }
        return restTemplate.exchange(
                "http://127.0.0.1:" + port
                        + "/api/v1/internal/policy-snapshot",
                HttpMethod.GET,
                new HttpEntity<>(headers),
                String.class
        );
    }

    private String etag(long revision) {
        return "\"policy-v1-r" + revision + "\"";
    }
}
