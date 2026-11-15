package com.ayushman.dns.admin.fleet;

import java.time.Instant;
import java.util.UUID;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** Minimal, permanent evidence that a resolver boot has already held a lease. */
@Entity
@Table(name = "resolver_boot_fences")
class ResolverBootFenceEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "resolver_id", nullable = false, length = 63)
    private String resolverId;

    @Column(name = "boot_id", nullable = false, length = 36)
    private String bootId;

    @Column(name = "session_generation", nullable = false)
    private long sessionGeneration;

    @Column(name = "first_seen_at", nullable = false, updatable = false)
    private Instant firstSeenAt;

    protected ResolverBootFenceEntity() {
        // Required by JPA.
    }

    ResolverBootFenceEntity(
            String resolverId,
            UUID bootId,
            long sessionGeneration,
            Instant firstSeenAt
    ) {
        this.resolverId = resolverId;
        this.bootId = bootId.toString();
        this.sessionGeneration = sessionGeneration;
        this.firstSeenAt = firstSeenAt;
    }

    String getResolverId() {
        return resolverId;
    }

    String getBootId() {
        return bootId;
    }

    long getSessionGeneration() {
        return sessionGeneration;
    }

    Instant getFirstSeenAt() {
        return firstSeenAt;
    }
}

