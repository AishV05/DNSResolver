package com.ayushman.dns.admin.fleet;

import jakarta.validation.constraints.NotNull;

/** Changes whether a registered resolver belongs to the expected fleet. */
public record UpdateResolverRegistrationRequest(@NotNull Boolean enabled) {
}
