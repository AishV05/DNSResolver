package com.ayushman.dns.cache;

import java.util.Objects;

import com.ayushman.dns.protocol.DnsMessage;

/** Immutable, already-aged view returned by the negative cache. */
public final class NegativeCacheEntry {

    private final DnsMessage response;
    private final long cachedAt;
    private final long expiresAt;
    private final long fixedRemainingTtl;

    NegativeCacheEntry(DnsMessage response, long remainingTtl) {
        this.response = Objects.requireNonNull(response, "response");
        this.cachedAt = 0;
        this.expiresAt = 0;
        this.fixedRemainingTtl = Math.max(remainingTtl, 0);
    }

    /**
     * Legacy wall-clock constructor retained for source compatibility.
     * New cache writes should pass a validated DNS response to
     * {@link NegativeCache#put} instead.
     */
    @Deprecated(forRemoval = false)
    public NegativeCacheEntry(
            DnsMessage response,
            long cachedAt,
            long expiresAt
    ) {
        this.response = Objects.requireNonNull(response, "response");
        this.cachedAt = cachedAt;
        this.expiresAt = expiresAt;
        this.fixedRemainingTtl = -1;
    }

    public DnsMessage response() {
        return response;
    }

    public boolean expired() {
        return fixedRemainingTtl >= 0
                ? fixedRemainingTtl == 0
                : System.currentTimeMillis() >= expiresAt;
    }

    public long remainingTtl() {
        if (fixedRemainingTtl >= 0) {
            return fixedRemainingTtl;
        }
        long remainingMillis = expiresAt - System.currentTimeMillis();
        return Math.max(remainingMillis / 1_000, 0);
    }

    public long cachedAt() {
        return cachedAt;
    }

    public long expiresAt() {
        return expiresAt;
    }

}
