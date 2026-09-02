package com.ayushman.dns.policy;

/**
 * Policy actions stored by the control plane. Enforcement is deliberately a
 * later data-plane concern, once versioned policy snapshots are available.
 */
public enum DnsPolicyAction {
    BLOCK
}
