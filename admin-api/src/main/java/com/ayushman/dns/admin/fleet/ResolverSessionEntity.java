package com.ayushman.dns.admin.fleet;

import java.time.Instant;
import java.util.UUID;

import com.ayushman.dns.fleet.ResolverPolicyMode;
import com.ayushman.dns.fleet.ResolverPolicySyncState;
import com.ayushman.dns.fleet.ResolverRuntimeReport;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;

@Entity
@Table(name = "resolver_sessions")
class ResolverSessionEntity {

    enum ReportAcceptance {
        ACCEPTED,
        IDEMPOTENT
    }

    @Id
    @Column(name = "session_id", nullable = false, length = 36)
    private String sessionId;

    @Column(name = "resolver_id", nullable = false, length = 63)
    private String resolverId;

    @Column(name = "boot_id", nullable = false, length = 36)
    private String bootId;

    @Column(name = "session_generation", nullable = false)
    private long sessionGeneration;

    @Column(name = "application_version", nullable = false, length = 64)
    private String applicationVersion;

    @Column(name = "started_at", nullable = false, updatable = false)
    private Instant startedAt;

    @Column(name = "superseded_at")
    private Instant supersededAt;

    @Column(name = "last_sequence")
    private Long lastSequence;

    @Enumerated(EnumType.STRING)
    @Column(name = "policy_mode", length = 16)
    private ResolverPolicyMode policyMode;

    @Column(name = "policy_snapshot_loaded")
    private Boolean policySnapshotLoaded;

    @Column(name = "policy_revision")
    private Long policyRevision;

    @Column(name = "policy_rule_count")
    private Integer policyRuleCount;

    @Column(name = "policy_ready")
    private Boolean policyReady;

    @Enumerated(EnumType.STRING)
    @Column(name = "policy_sync_state", length = 32)
    private ResolverPolicySyncState policySyncState;

    @Column(name = "last_report_received_at")
    private Instant lastReportReceivedAt;

    @Version
    @Column(nullable = false)
    private long version;

    protected ResolverSessionEntity() {
        // Required by JPA.
    }

    ResolverSessionEntity(
            UUID sessionId,
            String resolverId,
            UUID bootId,
            long sessionGeneration,
            String applicationVersion,
            Instant startedAt
    ) {
        this.sessionId = sessionId.toString();
        this.resolverId = resolverId;
        this.bootId = bootId.toString();
        this.sessionGeneration = sessionGeneration;
        this.applicationVersion = applicationVersion;
        this.startedAt = startedAt;
    }

    ReportAcceptance accept(ResolverRuntimeReport report, Instant receivedAt) {
        if (lastSequence != null) {
            if (report.sequence() < lastSequence) {
                throw new ResolverFleetConflictException(
                        "resolver report sequence is stale"
                );
            }
            if (report.sequence() == lastSequence) {
                if (samePayload(report)) {
                    return ReportAcceptance.IDEMPOTENT;
                }
                throw new ResolverFleetConflictException(
                        "resolver report sequence was already used"
                );
            }
        }

        lastSequence = report.sequence();
        policyMode = report.policyMode();
        policySnapshotLoaded = report.policySnapshotLoaded();
        policyRevision = report.policyRevision();
        policyRuleCount = report.policyRuleCount();
        policyReady = report.policyReady();
        policySyncState = report.policySyncState();
        lastReportReceivedAt = receivedAt;
        return ReportAcceptance.ACCEPTED;
    }

    private boolean samePayload(ResolverRuntimeReport report) {
        return report.sessionId().toString().equals(sessionId)
                && report.bootId().toString().equals(bootId)
                && report.sessionGeneration() == sessionGeneration
                && report.applicationVersion().equals(applicationVersion)
                && report.policyMode() == policyMode
                && report.policySnapshotLoaded() == policySnapshotLoaded
                && report.policyRevision() == policyRevision
                && report.policyRuleCount() == policyRuleCount
                && report.policyReady() == policyReady
                && report.policySyncState() == policySyncState;
    }

    void supersede(Instant now) {
        if (supersededAt == null) {
            supersededAt = now;
        }
    }

    boolean hasBoot(UUID candidateBootId) {
        return bootId.equals(candidateBootId.toString());
    }

    boolean hasApplicationVersion(String candidateVersion) {
        return applicationVersion.equals(candidateVersion);
    }

    boolean matchesEnvelope(ResolverRuntimeReport report) {
        return sessionId.equals(report.sessionId().toString())
                && bootId.equals(report.bootId().toString())
                && sessionGeneration == report.sessionGeneration()
                && applicationVersion.equals(report.applicationVersion());
    }

    UUID sessionUuid() {
        return UUID.fromString(sessionId);
    }

    UUID bootUuid() {
        return UUID.fromString(bootId);
    }

    String getSessionId() {
        return sessionId;
    }

    String getResolverId() {
        return resolverId;
    }

    long getSessionGeneration() {
        return sessionGeneration;
    }

    String getApplicationVersion() {
        return applicationVersion;
    }

    Instant getStartedAt() {
        return startedAt;
    }

    Instant getSupersededAt() {
        return supersededAt;
    }

    Long getLastSequence() {
        return lastSequence;
    }

    ResolverPolicyMode getPolicyMode() {
        return policyMode;
    }

    Boolean getPolicySnapshotLoaded() {
        return policySnapshotLoaded;
    }

    Long getPolicyRevision() {
        return policyRevision;
    }

    Integer getPolicyRuleCount() {
        return policyRuleCount;
    }

    Boolean getPolicyReady() {
        return policyReady;
    }

    ResolverPolicySyncState getPolicySyncState() {
        return policySyncState;
    }

    Instant getLastReportReceivedAt() {
        return lastReportReceivedAt;
    }

    long getVersion() {
        return version;
    }
}
