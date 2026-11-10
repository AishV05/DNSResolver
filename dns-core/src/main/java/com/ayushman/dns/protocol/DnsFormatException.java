package com.ayushman.dns.protocol;

/**
 * Indicates that DNS wire data is structurally invalid or truncated.
 */
public final class DnsFormatException extends RuntimeException {

    public DnsFormatException(String message) {
        super(message);
    }

    public DnsFormatException(String message, Throwable cause) {
        super(message, cause);
    }
}
