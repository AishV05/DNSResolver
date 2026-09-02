package com.ayushman.dns.policy;

import java.util.Objects;

/**
 * Framework-free representation of a DNS policy rule shared by control-plane
 * code and future policy-snapshot consumers.
 */
public record DnsPolicyRule(
        String domainName,
        DnsPolicyMatchType matchType,
        DnsPolicyAction action
) {

    public DnsPolicyRule {
        domainName = DomainNameNormalizer.normalize(domainName);
        matchType = Objects.requireNonNull(matchType, "matchType must not be null");
        action = Objects.requireNonNull(action, "action must not be null");
    }
}
