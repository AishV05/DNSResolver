package com.ayushman.dns.fleet;

/** Bounded policy synchronization state exposed to the control plane. */
public enum ResolverPolicySyncState {
    DISABLED,
    AWAITING_INITIAL_SNAPSHOT,
    HEALTHY,
    DEGRADED,
    STALE
}
