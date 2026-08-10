package com.ayushman.dns.cache;

public record NegativeCacheKey(
        String name,
        int type,
        int qclass,
        NegativeCacheType cacheType
) {
}