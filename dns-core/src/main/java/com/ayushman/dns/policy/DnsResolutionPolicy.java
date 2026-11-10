package com.ayushman.dns.policy;

import com.ayushman.dns.protocol.DnsQuestion;

/**
 * Immutable policy view used for one recursive-resolution transaction.
 *
 * <p>The caller captures the view before resolution starts, so every name in
 * one client request is evaluated against the same policy revision.</p>
 */
@FunctionalInterface
public interface DnsResolutionPolicy {

    DnsResolutionPolicy ALLOW_ALL = question -> {
        if (question == null) {
            throw new IllegalArgumentException(
                    "DNS policy question must not be null"
            );
        }
    };

    void requireAllowed(DnsQuestion question)
            throws DnsPolicyRefusedException,
            DnsPolicyUnavailableException;
}
