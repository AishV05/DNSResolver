package com.ayushman.dns.admin.policy;

import com.ayushman.dns.policy.DnsPolicyAction;
import com.ayushman.dns.policy.DnsPolicyMatchType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

public record UpdateDnsPolicyRuleRequest(
        @NotBlank @Size(max = 253) String domainName,
        @NotNull DnsPolicyMatchType matchType,
        @NotNull DnsPolicyAction action,
        @NotNull Boolean enabled
) {
}
