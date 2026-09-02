package com.ayushman.dns.admin.security;

import java.util.List;

public record AuthenticatedAdminResponse(
        long userId,
        String username,
        List<AdminRole> roles
) {

    public AuthenticatedAdminResponse {
        roles = List.copyOf(roles);
    }
}
