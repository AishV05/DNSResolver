package com.ayushman.dns.admin.fleet;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;

@Entity
@Table(name = "resolver_instances")
class ResolverRegistrationEntity {

    @Id
    @Column(name = "resolver_id", nullable = false, length = 63)
    private String resolverId;

    @Column(name = "identity_user_id", nullable = false, unique = true)
    private long identityUserId;

    @Column(nullable = false)
    private boolean enabled;

    @Column(name = "active_session_id", length = 36)
    private String activeSessionId;

    @Column(name = "last_session_generation", nullable = false)
    private long lastSessionGeneration;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Version
    @Column(nullable = false)
    private long version;

    protected ResolverRegistrationEntity() {
        // Required by JPA.
    }

    ResolverRegistrationEntity(
            String resolverId,
            long identityUserId,
            Instant createdAt
    ) {
        this.resolverId = resolverId;
        this.identityUserId = identityUserId;
        this.enabled = true;
        this.createdAt = createdAt;
        this.updatedAt = createdAt;
    }

    long nextGeneration() {
        if (lastSessionGeneration == Long.MAX_VALUE) {
            throw new ResolverFleetConflictException(
                    "resolver session generation is exhausted"
            );
        }
        return lastSessionGeneration + 1;
    }

    void activate(String sessionId, long generation, Instant now) {
        if (generation != lastSessionGeneration + 1 || generation < 1) {
            throw new IllegalArgumentException("invalid resolver session generation");
        }
        activeSessionId = sessionId;
        lastSessionGeneration = generation;
        updatedAt = now;
    }

    void disable(Instant now) {
        enabled = false;
        activeSessionId = null;
        updatedAt = now;
    }

    void enable(Instant now) {
        enabled = true;
        activeSessionId = null;
        updatedAt = now;
    }

    String getResolverId() {
        return resolverId;
    }

    long getIdentityUserId() {
        return identityUserId;
    }

    boolean isEnabled() {
        return enabled;
    }

    String getActiveSessionId() {
        return activeSessionId;
    }

    long getLastSessionGeneration() {
        return lastSessionGeneration;
    }

    Instant getCreatedAt() {
        return createdAt;
    }

    Instant getUpdatedAt() {
        return updatedAt;
    }

    long getVersion() {
        return version;
    }
}
