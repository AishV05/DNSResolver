package com.ayushman.dns.admin.security;

import java.time.Instant;

/**
 * Returned only when a token is issued. The caller must save {@code token}
 * then; no later endpoint can recover it.
 */
public record IssuedAdminApiTokenResponse(
        long id,
        long userId,
        String username,
        String tokenLabel,
        String token,
        Instant createdAt,
        Instant expiresAt
) {
}
