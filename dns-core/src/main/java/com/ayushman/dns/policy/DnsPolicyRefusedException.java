package com.ayushman.dns.policy;

/** Signals that the captured DNS policy denied a resolution name. */
public final class DnsPolicyRefusedException extends Exception {

    public DnsPolicyRefusedException() {
        super("DNS policy refused resolution");
    }
}
