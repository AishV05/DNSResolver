package com.ayushman.dns.admin.fleet;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import com.ayushman.dns.admin.security.AdminIdentityService;
import com.ayushman.dns.admin.security.IssuedAdminApiTokenResponse;
import com.ayushman.dns.fleet.ResolverInstanceId;
import com.ayushman.dns.fleet.ResolverRuntimeReport;
import com.ayushman.dns.fleet.ResolverSessionLease;
import com.ayushman.dns.fleet.ResolverSessionStart;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ResolverFleetService {

    private final ResolverRegistrationRepository registrationRepository;
    private final ResolverSessionRepository sessionRepository;
    private final ResolverBootFenceRepository bootFenceRepository;
    private final AdminIdentityService identityService;
    private final Clock clock;

    ResolverFleetService(
            ResolverRegistrationRepository registrationRepository,
            ResolverSessionRepository sessionRepository,
            ResolverBootFenceRepository bootFenceRepository,
            AdminIdentityService identityService,
            Clock clock
    ) {
        this.registrationRepository = registrationRepository;
        this.sessionRepository = sessionRepository;
        this.bootFenceRepository = bootFenceRepository;
        this.identityService = identityService;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    public List<ResolverRegistrationResponse> listRegistrations() {
        return registrationRepository.findAllByOrderByResolverIdAsc().stream()
                .map(this::toResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    public ResolverRegistrationResponse getRegistration(String resolverId) {
        String canonicalId = new ResolverInstanceId(resolverId).value();
        return toResponse(registrationRepository.findById(canonicalId)
                .orElseThrow(() -> new ResolverRegistrationNotFoundException(
                        canonicalId
                )));
    }

    @Transactional
    public ResolverRegistrationResponse updateRegistration(
            String resolverId,
            UpdateResolverRegistrationRequest request
    ) {
        String canonicalId = new ResolverInstanceId(resolverId).value();
        ResolverRegistrationEntity registration = registrationRepository
                .findLockedByResolverId(canonicalId)
                .orElseThrow(() -> new ResolverRegistrationNotFoundException(
                        canonicalId
                ));
        boolean enabled = request.enabled();
        if (registration.isEnabled() == enabled) {
            return toResponse(registration);
        }

        Instant now = clock.instant();
        ResolverSessionEntity active = activeSession(registration);
        if (active != null) {
            active.supersede(now);
        }
        identityService.setResolverAgentEnabled(
                registration.getIdentityUserId(),
                enabled
        );
        if (enabled) {
            registration.enable(now);
        } else {
            registration.disable(now);
        }
        return toResponse(registration);
    }

    @Transactional
    public RegisteredResolverResponse register(RegisterResolverRequest request) {
        String resolverId = new ResolverInstanceId(request.resolverId()).value();
        if (registrationRepository.existsById(resolverId)) {
            throw new ResolverFleetConflictException(
                    "resolver is already registered: " + resolverId
            );
        }

        IssuedAdminApiTokenResponse credential =
                identityService.createResolverAgent(
                        resolverId,
                        request.tokenExpiresAt()
                );
        Instant now = clock.instant();
        ResolverRegistrationEntity registration =
                registrationRepository.saveAndFlush(new ResolverRegistrationEntity(
                        resolverId,
                        credential.userId(),
                        now
                ));
        return new RegisteredResolverResponse(
                toResponse(registration),
                credential
        );
    }

    @Transactional
    public ResolverSessionStartResult startSession(
            long identityUserId,
            ResolverSessionStart request
    ) {
        ResolverRegistrationEntity registration = lockedRegistration(
                identityUserId
        );
        requireEnabled(registration);
        ResolverSessionEntity active = activeSession(registration);
        if (active != null && active.hasBoot(request.bootId())) {
            if (!active.hasApplicationVersion(request.applicationVersion())) {
                throw new ResolverFleetConflictException(
                        "resolver boot is already bound to another application version"
                );
            }
            return new ResolverSessionStartResult(toLease(registration, active), false);
        }

        if (bootFenceRepository.existsByResolverIdAndBootId(
                registration.getResolverId(),
                request.bootId().toString()
        )) {
            throw new ResolverFleetConflictException(
                    "resolver boot was already superseded"
            );
        }

        Instant now = clock.instant();
        if (active != null) {
            active.supersede(now);
        }
        long generation = registration.nextGeneration();
        bootFenceRepository.saveAndFlush(new ResolverBootFenceEntity(
                registration.getResolverId(),
                request.bootId(),
                generation,
                now
        ));
        ResolverSessionEntity created = sessionRepository.saveAndFlush(
                new ResolverSessionEntity(
                        UUID.randomUUID(),
                        registration.getResolverId(),
                        request.bootId(),
                        generation,
                        request.applicationVersion(),
                        now
                )
        );
        registration.activate(created.getSessionId(), generation, now);
        return new ResolverSessionStartResult(toLease(registration, created), true);
    }

    @Transactional
    public void acceptReport(
            long identityUserId,
            ResolverRuntimeReport report
    ) {
        ResolverRegistrationEntity registration = lockedRegistration(
                identityUserId
        );
        requireEnabled(registration);
        if (registration.getActiveSessionId() == null
                || !registration.getActiveSessionId().equals(
                        report.sessionId().toString()
                )) {
            throw new ResolverFleetConflictException(
                    "resolver report does not belong to the active session"
            );
        }

        ResolverSessionEntity session = sessionRepository.findById(
                registration.getActiveSessionId()
        ).orElseThrow(() -> new IllegalStateException(
                "active resolver session is missing"
        ));
        if (session.getSupersededAt() != null || !session.matchesEnvelope(report)) {
            throw new ResolverFleetConflictException(
                    "resolver report lease does not match the active session"
            );
        }
        session.accept(report, clock.instant());
    }

    private ResolverRegistrationEntity lockedRegistration(long identityUserId) {
        return registrationRepository.findLockedByIdentityUserId(identityUserId)
                .orElseThrow(UnregisteredResolverPrincipalException::new);
    }

    private void requireEnabled(ResolverRegistrationEntity registration) {
        if (!registration.isEnabled()) {
            throw new UnregisteredResolverPrincipalException();
        }
    }

    private ResolverSessionEntity activeSession(
            ResolverRegistrationEntity registration
    ) {
        if (registration.getActiveSessionId() == null) {
            return null;
        }
        return sessionRepository.findById(registration.getActiveSessionId())
                .orElseThrow(() -> new IllegalStateException(
                        "active resolver session is missing"
                ));
    }

    private ResolverSessionLease toLease(
            ResolverRegistrationEntity registration,
            ResolverSessionEntity session
    ) {
        return new ResolverSessionLease(
                registration.getResolverId(),
                session.sessionUuid(),
                session.bootUuid(),
                session.getSessionGeneration()
        );
    }

    private ResolverRegistrationResponse toResponse(
            ResolverRegistrationEntity registration
    ) {
        String activeSessionId = registration.getActiveSessionId();
        return new ResolverRegistrationResponse(
                registration.getResolverId(),
                registration.getIdentityUserId(),
                registration.isEnabled(),
                activeSessionId == null ? null : UUID.fromString(activeSessionId),
                registration.getLastSessionGeneration(),
                registration.getCreatedAt(),
                registration.getUpdatedAt(),
                registration.getVersion()
        );
    }
}
