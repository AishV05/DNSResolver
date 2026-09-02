package com.ayushman.dns.admin.policy;

import static org.assertj.core.api.Assertions.assertThat;

import com.ayushman.dns.admin.AdminApiTestAuthentication;
import com.ayushman.dns.policy.DnsPolicyAction;
import com.ayushman.dns.policy.DnsPolicyMatchType;
import org.junit.jupiter.api.BeforeEach;
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
        properties = "spring.datasource.url=jdbc:h2:mem:dns_policy_api_test;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE"
)
@ActiveProfiles("test")
class DnsPolicyRuleApiTest {

    @LocalServerPort
    private int port;

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private DnsPolicyRuleRepository repository;

    @BeforeEach
    void clearPolicies() {
        repository.deleteAll();
    }

    @Test
    void createsListsUpdatesAndDeletesAPolicyRule() {
        ResponseEntity<DnsPolicyRuleResponse> created = restTemplate.exchange(
                url(),
                HttpMethod.POST,
                AdminApiTestAuthentication.authenticated(
                        new CreateDnsPolicyRuleRequest(
                                "Example.COM.",
                                DnsPolicyMatchType.DOMAIN_AND_SUBDOMAINS,
                                DnsPolicyAction.BLOCK
                        )
                ),
                DnsPolicyRuleResponse.class
        );

        assertThat(created.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(created.getHeaders().getLocation()).isNotNull();
        assertThat(created.getBody()).isNotNull();
        assertThat(created.getBody().domainName()).isEqualTo("example.com");
        assertThat(created.getBody().enabled()).isTrue();

        long id = created.getBody().id();
        ResponseEntity<DnsPolicyRuleResponse[]> listed = restTemplate.exchange(
                url(),
                HttpMethod.GET,
                AdminApiTestAuthentication.authenticated(),
                DnsPolicyRuleResponse[].class
        );

        assertThat(listed.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(listed.getBody()).hasSize(1);

        ResponseEntity<DnsPolicyRuleResponse> updated = restTemplate.exchange(
                url("/" + id),
                HttpMethod.PUT,
                AdminApiTestAuthentication.authenticated(
                        new UpdateDnsPolicyRuleRequest(
                                "example.com",
                                DnsPolicyMatchType.EXACT,
                                DnsPolicyAction.BLOCK,
                                false
                        )
                ),
                DnsPolicyRuleResponse.class
        );

        assertThat(updated.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(updated.getBody()).isNotNull();
        assertThat(updated.getBody().matchType())
                .isEqualTo(DnsPolicyMatchType.EXACT);
        assertThat(updated.getBody().enabled()).isFalse();

        ResponseEntity<Void> deleted = restTemplate.exchange(
                url("/" + id),
                HttpMethod.DELETE,
                AdminApiTestAuthentication.authenticated(),
                Void.class
        );

        assertThat(deleted.getStatusCode()).isEqualTo(HttpStatus.NO_CONTENT);
        assertThat(repository.count()).isZero();
    }

    @Test
    void rejectsInvalidDuplicatesAndMissingRules() {
        CreateDnsPolicyRuleRequest valid = new CreateDnsPolicyRuleRequest(
                "example.com",
                DnsPolicyMatchType.EXACT,
                DnsPolicyAction.BLOCK
        );
        restTemplate.exchange(
                url(),
                HttpMethod.POST,
                AdminApiTestAuthentication.authenticated(valid),
                DnsPolicyRuleResponse.class
        );

        ResponseEntity<String> duplicate = restTemplate.exchange(
                url(),
                HttpMethod.POST,
                AdminApiTestAuthentication.authenticated(valid),
                String.class
        );
        ResponseEntity<String> invalid = restTemplate.exchange(
                url(),
                HttpMethod.POST,
                AdminApiTestAuthentication.authenticated(
                        new CreateDnsPolicyRuleRequest(
                                "invalid..example",
                                DnsPolicyMatchType.EXACT,
                                DnsPolicyAction.BLOCK
                        )
                ),
                String.class
        );
        ResponseEntity<String> missing = restTemplate.exchange(
                url("/99999"),
                HttpMethod.GET,
                AdminApiTestAuthentication.authenticated(),
                String.class
        );

        assertThat(duplicate.getStatusCode()).isEqualTo(HttpStatus.CONFLICT);
        assertThat(invalid.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(missing.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    private String url() {
        return url("");
    }

    private String url(String suffix) {
        return "http://127.0.0.1:" + port + "/api/v1/admin/policies" + suffix;
    }
}
