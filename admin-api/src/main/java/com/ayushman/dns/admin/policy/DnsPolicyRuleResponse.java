package com.ayushman.dns.admin.policy;

import java.time.Instant;

import com.ayushman.dns.policy.DnsPolicyAction;
import com.ayushman.dns.policy.DnsPolicyMatchType;

public record DnsPolicyRuleResponse(
        long id,
        String domainName,
        DnsPolicyMatchType matchType,
        DnsPolicyAction action,
        boolean enabled,
        Instant createdAt,
        Instant updatedAt,
        long version
) {
}
