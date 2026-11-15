package com.ayushman.dns.admin.fleet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;

import com.ayushman.dns.admin.policy.DnsPolicySnapshotService;
import com.ayushman.dns.admin.policy.DnsPolicySnapshotService.DnsPolicyPublicationStatus;
import com.ayushman.dns.fleet.ResolverFleetPolicyState;
import com.ayushman.dns.fleet.ResolverPolicyMode;
import com.ayushman.dns.fleet.ResolverPolicySyncState;
import com.ayushman.dns.fleet.ResolverRuntimeReport;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class ResolverFleetStatusServiceTest {

    private static final Instant NOW = Instant.parse("2026-11-13T00:00:00Z");
    private static final long FRESHNESS_MILLIS = 120_000;

    private ResolverRegistrationRepository registrations;
    private ResolverSessionRepository sessions;
    private DnsPolicySnapshotService policies;
    private ResolverFleetStatusService service;

    @BeforeEach
    void setUp() {
        registrations = mock(ResolverRegistrationRepository.class);
        sessions = mock(ResolverSessionRepository.class);
        policies = mock(DnsPolicySnapshotService.class);
        service = new ResolverFleetStatusService(
                registrations,
                sessions,
                policies,
                new ResolverFleetStatusProperties(FRESHNESS_MILLIS),
                Clock.fixed(NOW, ZoneOffset.UTC)
        );
        publish(0, 0);
        fleet(List.of(), List.of());
    }

    @Test
    void emptyOrEntirelyExcludedFleetIsUnobserved() {
        ResolverFleetStatusResponse empty = service.currentStatus();
        assertThat(empty.policyEnforcement()).isEqualTo(
                ResolverFleetPolicyState.DATA_PLANE_UNOBSERVED
        );
        assertThat(empty.expectedResolverCount()).isZero();

        ResolverRegistrationEntity disabled = registration("disabled", 1);
        disabled.disable(NOW.minusSeconds(1));
        fleet(List.of(disabled), List.of());
        ResolverFleetStatusResponse excluded = service.currentStatus();

        assertThat(excluded.policyEnforcement()).isEqualTo(
                ResolverFleetPolicyState.DATA_PLANE_UNOBSERVED
        );
        assertThat(excluded.registeredResolverCount()).isEqualTo(1);
        assertThat(excluded.expectedResolverCount()).isZero();
        assertThat(excluded.resolvers()).singleElement().satisfies(member -> {
            assertThat(member.expected()).isFalse();
            assertThat(member.state()).isEqualTo(
                    ResolverFleetMemberState.EXCLUDED_DISABLED
            );
        });
    }

    @Test
    void missingSessionAndMissingReportAreNotConverged() {
        ResolverRegistrationEntity registration = registration("resolver-a", 1);
        fleet(List.of(registration), List.of());
        assertMemberState(ResolverFleetMemberState.NO_ACTIVE_SESSION);

        ResolverSessionEntity session = session(registration, 1);
        fleet(List.of(registration), List.of(session));
        assertMemberState(ResolverFleetMemberState.NO_REPORT);
    }

    @Test
    void exactFreshnessBoundaryIsFreshAndOneMillisecondOlderIsStale() {
        ResolverRegistrationEntity registration = registration("resolver-a", 1);
        ResolverSessionEntity boundary = session(registration, 1);
        acceptHealthy(boundary, 1, NOW.minusMillis(FRESHNESS_MILLIS), 0, 0,
                ResolverPolicySyncState.HEALTHY);
        fleet(List.of(registration), List.of(boundary));

        ResolverFleetStatusResponse fresh = service.currentStatus();
        assertThat(fresh.policyEnforcement()).isEqualTo(
                ResolverFleetPolicyState.DATA_PLANE_CONVERGED
        );
        assertThat(fresh.freshResolverCount()).isEqualTo(1);
        assertThat(fresh.resolvers()).singleElement().satisfies(member -> {
            assertThat(member.reportAgeMillis()).isEqualTo(FRESHNESS_MILLIS);
            assertThat(member.reportFresh()).isTrue();
            assertThat(member.state()).isEqualTo(
                    ResolverFleetMemberState.CONVERGED
            );
        });

        ResolverSessionEntity stale = session(registration("resolver-b", 2), 1);
        ResolverRegistrationEntity staleRegistration = registrationFor(stale, 2);
        acceptHealthy(stale, 1, NOW.minusMillis(FRESHNESS_MILLIS + 1), 0, 0,
                ResolverPolicySyncState.HEALTHY);
        fleet(List.of(staleRegistration), List.of(stale));
        assertMemberState(ResolverFleetMemberState.REPORT_STALE);
    }

    @Test
    void degradedAndRuntimeStaleReportsCanStillConverge() {
        for (ResolverPolicySyncState state : List.of(
                ResolverPolicySyncState.DEGRADED,
                ResolverPolicySyncState.STALE
        )) {
            ResolverRegistrationEntity registration = registration(
                    "resolver-" + state.name().toLowerCase(),
                    state.ordinal() + 1
            );
            ResolverSessionEntity session = session(registration, 1);
            acceptHealthy(session, 1, NOW.minusSeconds(1), 0, 0, state);
            fleet(List.of(registration), List.of(session));

            assertThat(service.currentStatus().policyEnforcement()).isEqualTo(
                    ResolverFleetPolicyState.DATA_PLANE_CONVERGED
            );
        }
    }

    @Test
    void loadedRevisionZeroWithRulesConvergesAndFutureReceiptAgeClampsToZero() {
        publish(0, 2);
        ResolverRegistrationEntity registration = registration("resolver-a", 1);
        ResolverSessionEntity session = session(registration, 1);
        acceptHealthy(
                session,
                1,
                NOW.plusSeconds(5),
                0,
                2,
                ResolverPolicySyncState.HEALTHY
        );
        fleet(List.of(registration), List.of(session));

        ResolverFleetStatusResponse status = service.currentStatus();
        assertThat(status.policyEnforcement()).isEqualTo(
                ResolverFleetPolicyState.DATA_PLANE_CONVERGED
        );
        assertThat(status.resolvers()).singleElement().satisfies(member -> {
            assertThat(member.policySnapshotLoaded()).isTrue();
            assertThat(member.policyRevision()).isZero();
            assertThat(member.policyRuleCount()).isEqualTo(2);
            assertThat(member.reportAgeMillis()).isZero();
            assertThat(member.reportFresh()).isTrue();
        });
    }

    @Test
    void policyStateAndPublicationMismatchesHaveStableReasons() {
        assertReportedState(
                disabledReport(),
                ResolverFleetMemberState.POLICY_MODE_DISABLED,
                0,
                0
        );
        assertReportedState(
                awaitingReport(),
                ResolverFleetMemberState.POLICY_NOT_READY,
                0,
                0
        );
        assertReportedState(
                healthyReport(1, 8, 3, ResolverPolicySyncState.HEALTHY),
                ResolverFleetMemberState.REVISION_MISMATCH,
                9,
                3
        );
        assertReportedState(
                healthyReport(1, 9, 2, ResolverPolicySyncState.HEALTHY),
                ResolverFleetMemberState.RULE_COUNT_MISMATCH,
                9,
                3
        );
    }

    @Test
    void mixedFleetRequiresEveryExpectedMemberToConverge() {
        publish(4, 2);
        ResolverRegistrationEntity first = registration("a-resolver", 1);
        ResolverSessionEntity firstSession = session(first, 1);
        acceptHealthy(firstSession, 1, NOW, 4, 2,
                ResolverPolicySyncState.HEALTHY);
        ResolverRegistrationEntity second = registration("b-resolver", 2);
        ResolverSessionEntity secondSession = session(second, 1);
        ResolverRegistrationEntity excluded = registration("c-resolver", 3);
        excluded.disable(NOW);
        fleet(
                List.of(first, second, excluded),
                List.of(firstSession, secondSession)
        );

        ResolverFleetStatusResponse status = service.currentStatus();
        assertThat(status.policyEnforcement()).isEqualTo(
                ResolverFleetPolicyState.DATA_PLANE_NOT_CONVERGED
        );
        assertThat(status.expectedResolverCount()).isEqualTo(2);
        assertThat(status.convergedResolverCount()).isEqualTo(1);
        assertThat(status.resolvers())
                .extracting(ResolverFleetMemberStatusResponse::resolverId)
                .containsExactly("a-resolver", "b-resolver", "c-resolver");
    }

    private void assertReportedState(
            ResolverRuntimeReport report,
            ResolverFleetMemberState expectedState,
            long publishedRevision,
            long publishedRules
    ) {
        publish(publishedRevision, publishedRules);
        ResolverRegistrationEntity registration = registration("resolver-a", 1);
        ResolverSessionEntity session = session(registration, 1);
        session.accept(reportForSession(report, session), NOW);
        fleet(List.of(registration), List.of(session));
        assertMemberState(expectedState);
    }

    private void assertMemberState(ResolverFleetMemberState expected) {
        ResolverFleetStatusResponse status = service.currentStatus();
        assertThat(status.policyEnforcement()).isEqualTo(
                ResolverFleetPolicyState.DATA_PLANE_NOT_CONVERGED
        );
        assertThat(status.resolvers()).singleElement()
                .extracting(ResolverFleetMemberStatusResponse::state)
                .isEqualTo(expected);
    }

    private void publish(long revision, long rules) {
        when(policies.currentPublicationStatus()).thenReturn(
                new DnsPolicyPublicationStatus(revision, NOW, rules, rules)
        );
    }

    private void fleet(
            List<ResolverRegistrationEntity> registrationValues,
            List<ResolverSessionEntity> sessionValues
    ) {
        when(registrations.findAllLockedByOrderByResolverIdAsc())
                .thenReturn(registrationValues);
        when(sessions.findAllById(any())).thenReturn(sessionValues);
    }

    private ResolverRegistrationEntity registration(String id, long userId) {
        return new ResolverRegistrationEntity(id, userId, NOW.minusSeconds(10));
    }

    private ResolverRegistrationEntity registrationFor(
            ResolverSessionEntity session,
            long userId
    ) {
        ResolverRegistrationEntity registration = new ResolverRegistrationEntity(
                session.getResolverId(),
                userId,
                NOW.minusSeconds(10)
        );
        registration.activate(session.getSessionId(), 1, NOW.minusSeconds(9));
        return registration;
    }

    private ResolverSessionEntity session(
            ResolverRegistrationEntity registration,
            long generation
    ) {
        ResolverSessionEntity session = new ResolverSessionEntity(
                UUID.randomUUID(),
                registration.getResolverId(),
                UUID.randomUUID(),
                generation,
                "0.1.0-SNAPSHOT",
                NOW.minusSeconds(9)
        );
        registration.activate(
                session.getSessionId(),
                generation,
                NOW.minusSeconds(9)
        );
        return session;
    }

    private void acceptHealthy(
            ResolverSessionEntity session,
            long sequence,
            Instant receivedAt,
            long revision,
            int ruleCount,
            ResolverPolicySyncState syncState
    ) {
        session.accept(
                healthyReport(sequence, revision, ruleCount, syncState, session),
                receivedAt
        );
    }

    private ResolverRuntimeReport healthyReport(
            long sequence,
            long revision,
            int ruleCount,
            ResolverPolicySyncState syncState
    ) {
        return new ResolverRuntimeReport(
                UUID.randomUUID(),
                UUID.randomUUID(),
                1,
                sequence,
                "0.1.0-SNAPSHOT",
                ResolverPolicyMode.REQUIRED,
                true,
                revision,
                ruleCount,
                true,
                syncState
        );
    }

    private ResolverRuntimeReport healthyReport(
            long sequence,
            long revision,
            int ruleCount,
            ResolverPolicySyncState syncState,
            ResolverSessionEntity session
    ) {
        return new ResolverRuntimeReport(
                session.sessionUuid(),
                session.bootUuid(),
                session.getSessionGeneration(),
                sequence,
                session.getApplicationVersion(),
                ResolverPolicyMode.REQUIRED,
                true,
                revision,
                ruleCount,
                true,
                syncState
        );
    }

    private ResolverRuntimeReport disabledReport() {
        return new ResolverRuntimeReport(
                UUID.randomUUID(), UUID.randomUUID(), 1, 1, "0.1.0-SNAPSHOT",
                ResolverPolicyMode.DISABLED, false, 0, 0, true,
                ResolverPolicySyncState.DISABLED
        );
    }

    private ResolverRuntimeReport awaitingReport() {
        return new ResolverRuntimeReport(
                UUID.randomUUID(), UUID.randomUUID(), 1, 1, "0.1.0-SNAPSHOT",
                ResolverPolicyMode.REQUIRED, false, 0, 0, false,
                ResolverPolicySyncState.AWAITING_INITIAL_SNAPSHOT
        );
    }

    private ResolverRuntimeReport reportForSession(
            ResolverRuntimeReport source,
            ResolverSessionEntity session
    ) {
        return new ResolverRuntimeReport(
                session.sessionUuid(),
                session.bootUuid(),
                session.getSessionGeneration(),
                source.sequence(),
                session.getApplicationVersion(),
                source.policyMode(),
                source.policySnapshotLoaded(),
                source.policyRevision(),
                source.policyRuleCount(),
                source.policyReady(),
                source.policySyncState()
        );
    }
}
