package com.ayushman.dns.cache;

import com.ayushman.dns.protocol.DnsMessage;

public record CacheEntry(
        DnsMessage response,
        long expiresAt
) {

    public boolean expired() {
        return System.currentTimeMillis()
                > expiresAt;
    }
}