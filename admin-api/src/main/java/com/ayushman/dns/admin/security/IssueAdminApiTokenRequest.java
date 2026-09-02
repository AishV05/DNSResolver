package com.ayushman.dns.admin.security;

import java.time.Instant;

import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record IssueAdminApiTokenRequest(
        @NotBlank @Size(max = 100) String tokenLabel,
        @Future Instant expiresAt
) {
}
