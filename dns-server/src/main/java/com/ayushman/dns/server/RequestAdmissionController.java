package com.ayushman.dns.server;

import java.net.DatagramPacket;
import java.net.InetAddress;

/**
 * Keeps oversized or rate-limited packets out of the resolver worker queue.
 */
public final class RequestAdmissionController {

    public enum Decision {
        ADMITTED,
        OVERSIZED,
        RATE_LIMITED
    }

    public static final int DEFAULT_MAX_REQUEST_BYTES =
            1_232;

    private final int maxRequestBytes;
    private final ClientRateLimiter rateLimiter;

    public RequestAdmissionController(
            int maxRequestBytes,
            ClientRateLimiter rateLimiter
    ) {

        if (maxRequestBytes <= 0 || maxRequestBytes > 65_535) {
            throw new IllegalArgumentException(
                    "maxRequestBytes must be between 1 and 65535"
            );
        }

        if (rateLimiter == null) {
            throw new IllegalArgumentException(
                    "rateLimiter must not be null"
            );
        }

        this.maxRequestBytes = maxRequestBytes;
        this.rateLimiter = rateLimiter;
    }

    public boolean allow(
            DatagramPacket requestPacket
    ) {

        return decide(requestPacket) == Decision.ADMITTED;
    }

    public Decision decide(
            DatagramPacket requestPacket
    ) {

        if (requestPacket == null) {
            return Decision.OVERSIZED;
        }

        return decide(
                requestPacket.getAddress(),
                requestPacket.getLength()
        );
    }

    Decision decide(
            InetAddress client,
            int requestLength
    ) {

        if (client == null
                || requestLength <= 0
                || requestLength > maxRequestBytes) {
            return Decision.OVERSIZED;
        }

        if (!rateLimiter.tryAcquire(client)) {
            return Decision.RATE_LIMITED;
        }

        return Decision.ADMITTED;
    }

    /**
     * One extra byte lets the server detect a packet over the configured cap.
     */
    public int receiveBufferSize() {
        return maxRequestBytes + 1;
    }
}
