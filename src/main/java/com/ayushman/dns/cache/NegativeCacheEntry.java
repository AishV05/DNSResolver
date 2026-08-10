package com.ayushman.dns.cache;

import com.ayushman.dns.protocol.DnsMessage;

public record NegativeCacheEntry(
        DnsMessage response,
        long cachedAt,
        long expiresAt
) {

    public boolean expired() {
        return System.currentTimeMillis() >= expiresAt;
    }

    public long remainingTtl() {

        long remaining =
                expiresAt - System.currentTimeMillis();

        if (remaining <= 0) {
            return 0;
        }

        return remaining / 1000;
    }
}