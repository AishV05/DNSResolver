package com.ayushman.dns.fleet;

/** Aggregate policy convergence state computed by the control plane. */
public enum ResolverFleetPolicyState {
    DATA_PLANE_UNOBSERVED,
    DATA_PLANE_NOT_CONVERGED,
    DATA_PLANE_CONVERGED
}
