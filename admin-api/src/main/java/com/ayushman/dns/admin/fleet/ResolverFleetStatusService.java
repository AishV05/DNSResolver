package com.ayushman.dns.admin.fleet;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.ayushman.dns.admin.policy.DnsPolicySnapshotService;
import com.ayushman.dns.admin.policy.DnsPolicySnapshotService.DnsPolicyPublicationStatus;
import com.ayushman.dns.fleet.ResolverFleetPolicyState;
import com.ayushman.dns.fleet.ResolverPolicyMode;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

/** Computes one transactionally consistent fleet convergence snapshot. */
@Service
public class ResolverFleetStatusService {

    private final ResolverRegistrationRepository registrationRepository;
    private final ResolverSessionRepository sessionRepository;
    private final DnsPolicySnapshotService policySnapshotService;
    private final ResolverFleetStatusProperties properties;
    private final Clock clock;

    ResolverFleetStatusService(
            ResolverRegistrationRepository registrationRepository,
            ResolverSessionRepository sessionRepository,
            DnsPolicySnapshotService policySnapshotService,
            ResolverFleetStatusProperties properties,
            Clock clock
    ) {
        this.registrationRepository = registrationRepository;
        this.sessionRepository = sessionRepository;
        this.policySnapshotService = policySnapshotService;
        this.properties = properties;
        this.clock = clock;
    }

    /*
     * The policy-state and registration rows are explicitly read-locked in a
     * fixed order. READ_COMMITTED lets PostgreSQL wait for an overlapping
     * session/report transaction before acquiring those locks; REPEATABLE_READ
     * could instead abort this read-only status request with a serialization
     * failure after a concurrent lifecycle commit.
     */
    @Transactional(isolation = Isolation.READ_COMMITTED)
    public ResolverFleetStatusResponse currentStatus() {
        DnsPolicyPublicationStatus publication =
                policySnapshotService.currentPublicationStatus();
        Instant evaluatedAt = clock.instant();
        List<ResolverRegistrationEntity> registrations =
                registrationRepository.findAllLockedByOrderByResolverIdAsc();
        Map<String, ResolverSessionEntity> sessions = activeSessions(
                registrations
        );

        long expected = 0;
        long fresh = 0;
        long converged = 0;
        java.util.ArrayList<ResolverFleetMemberStatusResponse> members =
                new java.util.ArrayList<>(registrations.size());

        for (ResolverRegistrationEntity registration : registrations) {
            ResolverSessionEntity session = sessions.get(
                    registration.getActiveSessionId()
            );
            ResolverFleetMemberStatusResponse member = evaluateMember(
                    registration,
                    session,
                    publication,
                    evaluatedAt
            );
            members.add(member);
            if (member.expected()) {
                expected++;
                if (Boolean.TRUE.equals(member.reportFresh())) {
                    fresh++;
                }
                if (member.state() == ResolverFleetMemberState.CONVERGED) {
                    converged++;
                }
            }
        }

        ResolverFleetPolicyState state;
        if (expected == 0) {
            state = ResolverFleetPolicyState.DATA_PLANE_UNOBSERVED;
        } else if (converged == expected) {
            state = ResolverFleetPolicyState.DATA_PLANE_CONVERGED;
        } else {
            state = ResolverFleetPolicyState.DATA_PLANE_NOT_CONVERGED;
        }

        return new ResolverFleetStatusResponse(
                ResolverFleetStatusResponse.CURRENT_SCHEMA_VERSION,
                evaluatedAt,
                properties.reportFreshnessMillis(),
                publication.revision(),
                publication.persistedRuleCount(),
                publication.enabledRuleCount(),
                state,
                registrations.size(),
                expected,
                fresh,
                converged,
                members
        );
    }

    private Map<String, ResolverSessionEntity> activeSessions(
            List<ResolverRegistrationEntity> registrations
    ) {
        List<String> ids = registrations.stream()
                .map(ResolverRegistrationEntity::getActiveSessionId)
                .filter(java.util.Objects::nonNull)
                .distinct()
                .toList();
        Map<String, ResolverSessionEntity> sessions = new HashMap<>();
        sessionRepository.findAllById(ids).forEach(session ->
                sessions.put(session.getSessionId(), session)
        );
        return sessions;
    }

    private ResolverFleetMemberStatusResponse evaluateMember(
            ResolverRegistrationEntity registration,
            ResolverSessionEntity session,
            DnsPolicyPublicationStatus publication,
            Instant evaluatedAt
    ) {
        if (!registration.isEnabled()) {
            return emptyMember(
                    registration.getResolverId(),
                    false,
                    ResolverFleetMemberState.EXCLUDED_DISABLED
            );
        }
        if (!isCurrentSession(registration, session)) {
            return emptyMember(
                    registration.getResolverId(),
                    true,
                    ResolverFleetMemberState.NO_ACTIVE_SESSION
            );
        }
        if (session.getLastSequence() == null
                || session.getLastReportReceivedAt() == null) {
            return member(
                    registration.getResolverId(),
                    session,
                    ResolverFleetMemberState.NO_REPORT,
                    null,
                    null
            );
        }

        long ageMillis = reportAgeMillis(
                session.getLastReportReceivedAt(),
                evaluatedAt
        );
        boolean reportFresh = !session.getLastReportReceivedAt().isBefore(
                evaluatedAt.minusMillis(properties.reportFreshnessMillis())
        );
        ResolverFleetMemberState state = classifyReportedMember(
                session,
                publication,
                reportFresh
        );
        return member(
                registration.getResolverId(),
                session,
                state,
                ageMillis,
                reportFresh
        );
    }

    private boolean isCurrentSession(
            ResolverRegistrationEntity registration,
            ResolverSessionEntity session
    ) {
        return registration.getActiveSessionId() != null
                && session != null
                && registration.getActiveSessionId().equals(
                        session.getSessionId()
                )
                && registration.getLastSessionGeneration()
                        == session.getSessionGeneration()
                && session.getSupersededAt() == null;
    }

    private ResolverFleetMemberState classifyReportedMember(
            ResolverSessionEntity session,
            DnsPolicyPublicationStatus publication,
            boolean reportFresh
    ) {
        if (!reportFresh) {
            return ResolverFleetMemberState.REPORT_STALE;
        }
        if (session.getPolicyMode() != ResolverPolicyMode.REQUIRED) {
            return ResolverFleetMemberState.POLICY_MODE_DISABLED;
        }
        if (!Boolean.TRUE.equals(session.getPolicySnapshotLoaded())
                || !Boolean.TRUE.equals(session.getPolicyReady())) {
            return ResolverFleetMemberState.POLICY_NOT_READY;
        }
        if (session.getPolicyRevision() == null
                || session.getPolicyRevision() != publication.revision()) {
            return ResolverFleetMemberState.REVISION_MISMATCH;
        }
        if (session.getPolicyRuleCount() == null
                || session.getPolicyRuleCount().longValue()
                        != publication.enabledRuleCount()) {
            return ResolverFleetMemberState.RULE_COUNT_MISMATCH;
        }
        return ResolverFleetMemberState.CONVERGED;
    }

    private ResolverFleetMemberStatusResponse emptyMember(
            String resolverId,
            boolean expected,
            ResolverFleetMemberState state
    ) {
        return new ResolverFleetMemberStatusResponse(
                resolverId,
                expected,
                state,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null
        );
    }

    private ResolverFleetMemberStatusResponse member(
            String resolverId,
            ResolverSessionEntity session,
            ResolverFleetMemberState state,
            Long reportAgeMillis,
            Boolean reportFresh
    ) {
        return new ResolverFleetMemberStatusResponse(
                resolverId,
                true,
                state,
                session.getSessionGeneration(),
                session.getApplicationVersion(),
                session.getLastReportReceivedAt(),
                reportAgeMillis,
                reportFresh,
                session.getPolicyMode(),
                session.getPolicySnapshotLoaded(),
                session.getPolicyRevision(),
                session.getPolicyRuleCount(),
                session.getPolicyReady(),
                session.getPolicySyncState()
        );
    }

    private long reportAgeMillis(Instant receivedAt, Instant evaluatedAt) {
        if (!receivedAt.isBefore(evaluatedAt)) {
            return 0;
        }
        return Duration.between(receivedAt, evaluatedAt).toMillis();
    }
}
