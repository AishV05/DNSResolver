package com.ayushman.dns.admin.fleet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;

import com.ayushman.dns.fleet.ResolverSessionStart;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.MOCK,
        properties = "spring.datasource.url=jdbc:h2:mem:resolver_session_retention_test;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE"
)
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "dns.admin.bootstrap.username=test-bootstrap-admin",
        "dns.admin.bootstrap.token=test-bootstrap-token-at-least-thirty-two-characters"
})
class ResolverSessionRetentionIntegrationTest {

    @Autowired
    private ResolverFleetService fleetService;

    @Autowired
    private ResolverSessionPruner pruner;

    @Autowired
    private ResolverSessionRepository sessionRepository;

    @Autowired
    private ResolverBootFenceRepository fenceRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void pruningDetailedHistoryKeepsPermanentBootFencingAndActiveSession() {
        long fencesBefore = fenceRepository.count();
        RegisteredResolverResponse registration = fleetService.register(
                new RegisterResolverRequest("retention-resolver", null)
        );
        long identity = registration.resolver().identityUserId();
        UUID firstBoot = UUID.randomUUID();
        UUID secondBoot = UUID.randomUUID();
        UUID thirdBoot = UUID.randomUUID();

        var first = fleetService.startSession(
                identity,
                new ResolverSessionStart(firstBoot, "0.1.0")
        ).lease();
        var second = fleetService.startSession(
                identity,
                new ResolverSessionStart(secondBoot, "0.1.0")
        ).lease();
        var third = fleetService.startSession(
                identity,
                new ResolverSessionStart(thirdBoot, "0.1.0")
        ).lease();

        Instant cutoff = Instant.parse("2026-11-15T00:00:00Z");
        jdbcTemplate.update(
                "UPDATE resolver_sessions SET superseded_at = ? WHERE session_id = ?",
                Timestamp.from(cutoff.minusSeconds(2)),
                first.sessionId().toString()
        );
        jdbcTemplate.update(
                "UPDATE resolver_sessions SET superseded_at = ? WHERE session_id = ?",
                Timestamp.from(cutoff),
                second.sessionId().toString()
        );

        assertThat(pruner.pruneBatch(cutoff, 10)).isEqualTo(1);
        assertThat(sessionRepository.findById(first.sessionId().toString()))
                .isEmpty();
        assertThat(sessionRepository.findById(second.sessionId().toString()))
                .isPresent();
        assertThat(sessionRepository.findById(third.sessionId().toString()))
                .isPresent();
        assertThat(fenceRepository.count()).isEqualTo(fencesBefore + 3);

        assertThatThrownBy(() -> fleetService.startSession(
                identity,
                new ResolverSessionStart(firstBoot, "0.1.0")
        )).isInstanceOf(ResolverFleetConflictException.class);
        ResolverRegistrationResponse current = fleetService.getRegistration(
                "retention-resolver"
        );
        assertThat(current.activeSessionId()).isEqualTo(third.sessionId());
        assertThat(current.lastSessionGeneration()).isEqualTo(3);

        var fourth = fleetService.startSession(
                identity,
                new ResolverSessionStart(UUID.randomUUID(), "0.1.0")
        ).lease();
        assertThat(fourth.sessionGeneration()).isEqualTo(4);
    }

    @Test
    void pruningIsBatchBoundedIdempotentAndNeverDeletesActiveRows() {
        long sessionsBefore = sessionRepository.count();
        long fencesBefore = fenceRepository.count();
        RegisteredResolverResponse registration = fleetService.register(
                new RegisterResolverRequest("batch-resolver", null)
        );
        long identity = registration.resolver().identityUserId();
        var first = fleetService.startSession(
                identity,
                new ResolverSessionStart(UUID.randomUUID(), "0.1.0")
        ).lease();
        var second = fleetService.startSession(
                identity,
                new ResolverSessionStart(UUID.randomUUID(), "0.1.0")
        ).lease();
        var active = fleetService.startSession(
                identity,
                new ResolverSessionStart(UUID.randomUUID(), "0.1.0")
        ).lease();

        Instant cutoff = Instant.parse("2026-11-15T00:00:00Z");
        jdbcTemplate.update(
                "UPDATE resolver_sessions SET superseded_at = ? WHERE session_id IN (?, ?)",
                Timestamp.from(cutoff.minusSeconds(1)),
                first.sessionId().toString(),
                second.sessionId().toString()
        );

        assertThat(pruner.pruneBatch(cutoff, 1)).isEqualTo(1);
        assertThat(sessionRepository.count()).isEqualTo(sessionsBefore + 2);
        assertThat(pruner.pruneBatch(cutoff, 1)).isEqualTo(1);
        assertThat(pruner.pruneBatch(cutoff, 1)).isZero();
        assertThat(sessionRepository.findById(active.sessionId().toString()))
                .isPresent();
        assertThat(fenceRepository.count()).isEqualTo(fencesBefore + 3);
    }
}
