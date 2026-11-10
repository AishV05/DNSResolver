package com.ayushman.dns.cache;

/**
 * Legacy wall-clock cache view retained for source compatibility.
 *
 * @deprecated The bounded resolver cache owns its monotonic entries
 * internally and returns {@link CachedDnsData} directly.
 */
@Deprecated(forRemoval = false)
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
        long remainingMillis = expiresAt - System.currentTimeMillis();
        return Math.max(remainingMillis / 1_000, 0);
    }
}
