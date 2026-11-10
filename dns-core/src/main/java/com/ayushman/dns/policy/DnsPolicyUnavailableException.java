package com.ayushman.dns.policy;

/** Signals that no usable policy view is available for resolution. */
public final class DnsPolicyUnavailableException extends Exception {

    public DnsPolicyUnavailableException() {
        super("DNS policy is unavailable");
    }

    public DnsPolicyUnavailableException(Throwable cause) {
        super("DNS policy is unavailable", cause);
    }
}
