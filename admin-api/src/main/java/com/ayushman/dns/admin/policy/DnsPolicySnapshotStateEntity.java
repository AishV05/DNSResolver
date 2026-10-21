package com.ayushman.dns.admin.policy;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * Singleton publication state used to serialize policy writes and snapshots.
 */
@Entity
@Table(name = "dns_policy_snapshot_state")
class DnsPolicySnapshotStateEntity {

    static final int SINGLETON_ID = 1;

    @Id
    @Column(name = "singleton_id", nullable = false)
    private Integer singletonId;

    @Column(nullable = false)
    private long revision;

    @Column(name = "published_at", nullable = false)
    private Instant publishedAt;

    protected DnsPolicySnapshotStateEntity() {
        // Required by JPA.
    }

    long getRevision() {
        return revision;
    }

    Instant getPublishedAt() {
        return publishedAt;
    }

    void advance(Instant publicationTime) {
        revision = Math.addExact(revision, 1L);
        publishedAt = publicationTime;
    }
}
