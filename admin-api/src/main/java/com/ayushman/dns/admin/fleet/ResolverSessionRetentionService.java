package com.ayushman.dns.admin.fleet;

import java.time.Clock;
import java.time.Instant;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Reads aggregate retention state without exposing session or boot identifiers. */
@Service
public class ResolverSessionRetentionService {

    private final ResolverSessionRepository sessionRepository;
    private final ResolverBootFenceRepository fenceRepository;
    private final ResolverSessionRetentionProperties properties;
    private final ResolverSessionRetentionTelemetry telemetry;
    private final Clock clock;

    ResolverSessionRetentionService(
            ResolverSessionRepository sessionRepository,
            ResolverBootFenceRepository fenceRepository,
            ResolverSessionRetentionProperties properties,
            ResolverSessionRetentionTelemetry telemetry,
            Clock clock
    ) {
        this.sessionRepository = sessionRepository;
        this.fenceRepository = fenceRepository;
        this.properties = properties;
        this.telemetry = telemetry;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    public ResolverSessionRetentionSnapshot currentSnapshot() {
        Instant cutoff = clock.instant().minusMillis(properties.retentionMillis());
        ResolverSessionRetentionTelemetry.Snapshot state = telemetry.snapshot();
        return new ResolverSessionRetentionSnapshot(
                sessionRepository.countBySupersededAtIsNull(),
                sessionRepository.countBySupersededAtIsNotNull(),
                sessionRepository.countRetentionEligible(cutoff),
                fenceRepository.count(),
                properties.retentionMillis(),
                state.successfulRuns(),
                state.failedRuns(),
                state.deletedSessions(),
                state.lastSuccessEpochMillis(),
                state.consecutiveFailures(),
                state.saturated()
        );
    }
}

