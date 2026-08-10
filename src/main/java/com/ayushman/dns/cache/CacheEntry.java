package com.ayushman.dns.cache;

public record CacheEntry(

        CachedDnsData data,

        long cachedAt,

        long expiresAt,

        long originalTtl

) {

    public boolean expired() {

        return System.currentTimeMillis() >= expiresAt;
    }

    public long remainingTtl() {

        long remaining =
                (expiresAt - System.currentTimeMillis()) / 1000;

        return Math.max(remaining, 0);
    }
}