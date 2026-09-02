package com.ayushman.dns.admin.security;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.ForeignKey;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;

@Entity
@Table(
        name = "admin_api_tokens",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_admin_api_tokens_hash",
                columnNames = "token_hash"
        )
)
class AdminApiTokenEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(
            name = "user_id",
            nullable = false,
            foreignKey = @ForeignKey(name = "fk_admin_api_tokens_user")
    )
    private AdminUserEntity user;

    @Column(name = "token_hash", nullable = false, length = 64)
    private String tokenHash;

    @Column(name = "token_label", nullable = false, length = 100)
    private String tokenLabel;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "last_used_at")
    private Instant lastUsedAt;

    protected AdminApiTokenEntity() {
        // Required by JPA.
    }

    AdminApiTokenEntity(
            AdminUserEntity user,
            String tokenHash,
            String tokenLabel,
            Instant expiresAt
    ) {
        this.user = user;
        this.tokenHash = tokenHash;
        this.tokenLabel = tokenLabel;
        this.expiresAt = expiresAt;
    }

    @PrePersist
    void initializeTimestamp() {
        createdAt = Instant.now();
    }

    boolean isUsableAt(Instant now) {
        return user.isEnabled()
                && revokedAt == null
                && (expiresAt == null || expiresAt.isAfter(now));
    }

    void revokeAt(Instant now) {
        if (revokedAt == null) {
            revokedAt = now;
        }
    }

    Long getId() {
        return id;
    }

    AdminUserEntity getUser() {
        return user;
    }

    String getTokenHash() {
        return tokenHash;
    }

    String getTokenLabel() {
        return tokenLabel;
    }

    Instant getExpiresAt() {
        return expiresAt;
    }

    Instant getRevokedAt() {
        return revokedAt;
    }

    Instant getCreatedAt() {
        return createdAt;
    }

    Instant getLastUsedAt() {
        return lastUsedAt;
    }

}
