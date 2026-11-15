package com.ayushman.dns.admin.fleet;

/** Stable diagnostic reason for one resolver's convergence result. */
public enum ResolverFleetMemberState {
    EXCLUDED_DISABLED,
    NO_ACTIVE_SESSION,
    NO_REPORT,
    REPORT_STALE,
    POLICY_MODE_DISABLED,
    POLICY_NOT_READY,
    REVISION_MISMATCH,
    RULE_COUNT_MISMATCH,
    CONVERGED
}
