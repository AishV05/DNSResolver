package com.ayushman.dns.admin.security;

import java.time.Instant;
import java.util.List;

public record AdminUserResponse(
        long id,
        String username,
        boolean enabled,
        List<AdminRole> roles,
        Instant createdAt,
        Instant updatedAt,
        long version
) {

    public AdminUserResponse {
        roles = List.copyOf(roles);
    }
}
