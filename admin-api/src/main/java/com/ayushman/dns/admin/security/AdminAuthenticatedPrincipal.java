package com.ayushman.dns.admin.security;

import java.security.Principal;
import java.util.Set;

/**
 * Authentication state derived from a valid opaque API token.
 */
public record AdminAuthenticatedPrincipal(
        long userId,
        String username,
        Set<AdminRole> roles
) implements Principal {

    public AdminAuthenticatedPrincipal {
        roles = Set.copyOf(roles);
    }

    @Override
    public String getName() {
        return username;
    }
}
