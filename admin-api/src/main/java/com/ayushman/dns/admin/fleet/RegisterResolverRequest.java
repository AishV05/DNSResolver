package com.ayushman.dns.admin.fleet;

import java.time.Instant;

import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record RegisterResolverRequest(
        @NotBlank @Size(max = 63) String resolverId,
        @Future Instant tokenExpiresAt
) {
}
