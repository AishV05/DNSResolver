package com.ayushman.dns.admin.security;

import java.time.Instant;

/**
 * Safe token metadata. It intentionally excludes both the raw token and its
 * persisted hash.
 */
public record AdminApiTokenResponse(
        long id,
        long userId,
        String username,
        String tokenLabel,
        Instant createdAt,
        Instant expiresAt,
        Instant revokedAt,
        Instant lastUsedAt,
        boolean active
) {
}
