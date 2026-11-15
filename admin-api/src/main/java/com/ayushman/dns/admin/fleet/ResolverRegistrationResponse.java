package com.ayushman.dns.admin.fleet;

import java.time.Instant;
import java.util.UUID;

public record ResolverRegistrationResponse(
        String resolverId,
        long identityUserId,
        boolean enabled,
        UUID activeSessionId,
        long lastSessionGeneration,
        Instant createdAt,
        Instant updatedAt,
        long version
) {
}
