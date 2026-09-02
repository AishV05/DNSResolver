package com.ayushman.dns.policy;

/**
 * Defines whether a policy applies only to a name or also to its descendants.
 */
public enum DnsPolicyMatchType {
    EXACT,
    DOMAIN_AND_SUBDOMAINS
}
