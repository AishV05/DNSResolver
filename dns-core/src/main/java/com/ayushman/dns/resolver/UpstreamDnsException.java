package com.ayushman.dns.resolver;

import java.io.IOException;

/**
 * Signals that an upstream DNS server could not provide a valid response.
 */
public class UpstreamDnsException extends IOException {

    public UpstreamDnsException(
            String message
    ) {
        super(message);
    }

    public UpstreamDnsException(
            String message,
            Throwable cause
    ) {
        super(message, cause);
    }
}
