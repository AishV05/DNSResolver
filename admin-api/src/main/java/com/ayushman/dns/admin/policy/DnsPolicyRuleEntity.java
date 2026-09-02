package com.ayushman.dns.admin.policy;

import java.time.Instant;

import com.ayushman.dns.policy.DnsPolicyAction;
import com.ayushman.dns.policy.DnsPolicyMatchType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import jakarta.persistence.Version;

/**
 * Durable control-plane record. The UDP server does not read this entity
 * directly; policy distribution is intentionally introduced in a later phase.
 */
@Entity
@Table(
        name = "dns_policy_rules",
        uniqueConstraints = @UniqueConstraint(
                name = "uk_dns_policy_rules_domain_match",
                columnNames = {"domain_name", "match_type"}
        )
)
public class DnsPolicyRuleEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "domain_name", nullable = false, length = 253)
    private String domainName;

    @Enumerated(EnumType.STRING)
    @Column(name = "match_type", nullable = false, length = 32)
    private DnsPolicyMatchType matchType;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    private DnsPolicyAction action;

    @Column(nullable = false)
    private boolean enabled;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Version
    @Column(nullable = false)
    private long version;

    protected DnsPolicyRuleEntity() {
        // Required by JPA.
    }

    DnsPolicyRuleEntity(
            String domainName,
            DnsPolicyMatchType matchType,
            DnsPolicyAction action,
            boolean enabled
    ) {
        this.domainName = domainName;
        this.matchType = matchType;
        this.action = action;
        this.enabled = enabled;
    }

    void update(
            String domainName,
            DnsPolicyMatchType matchType,
            DnsPolicyAction action,
            boolean enabled
    ) {
        this.domainName = domainName;
        this.matchType = matchType;
        this.action = action;
        this.enabled = enabled;
    }

    @PrePersist
    void initializeTimestamps() {
        Instant now = Instant.now();
        createdAt = now;
        updatedAt = now;
    }

    @PreUpdate
    void updateTimestamp() {
        updatedAt = Instant.now();
    }

    Long getId() {
        return id;
    }

    String getDomainName() {
        return domainName;
    }

    DnsPolicyMatchType getMatchType() {
        return matchType;
    }

    DnsPolicyAction getAction() {
        return action;
    }

    boolean isEnabled() {
        return enabled;
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
