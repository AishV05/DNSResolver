package com.ayushman.dns.policy;

/**
 * Result of evaluating one DNS question against an immutable policy snapshot.
 *
 * <p>{@link #ALLOW} means that no blocking rule matched. It is not a stored
 * allow-list rule.</p>
 */
public enum DnsPolicyDecision {
    ALLOW,
    BLOCK
}
