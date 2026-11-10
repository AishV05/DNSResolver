package com.ayushman.dns.cache;

public record NegativeCacheKey(
        CanonicalDnsName name,
        int type,
        int qclass,
        NegativeCacheType cacheType
) {
}
