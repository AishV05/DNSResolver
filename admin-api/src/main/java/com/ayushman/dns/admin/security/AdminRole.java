package com.ayushman.dns.admin.security;

/**
 * Roles granted to administrative API principals.
 */
public enum AdminRole {
    VIEWER,
    POLICY_EDITOR,
    POLICY_SNAPSHOT_READER,
    FLEET_METRICS_READER,
    RESOLVER_AGENT,
    ADMIN
}
