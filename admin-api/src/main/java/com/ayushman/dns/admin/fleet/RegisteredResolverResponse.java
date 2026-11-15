package com.ayushman.dns.admin.fleet;

import com.ayushman.dns.admin.security.IssuedAdminApiTokenResponse;

/** Returned once when a resolver registration and its first token are made. */
public record RegisteredResolverResponse(
        ResolverRegistrationResponse resolver,
        IssuedAdminApiTokenResponse credential
) {
}
