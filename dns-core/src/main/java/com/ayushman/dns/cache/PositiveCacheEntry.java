package com.ayushman.dns.cache;

/** Internal monotonic-clock entry for one complete positive outcome. */
record PositiveCacheEntry(
        CachedDnsData data,
        long cachedAtNanos,
        long lifetimeNanos,
        long minimumTtlSeconds
) {
    boolean expired(long nowNanos) {
        return nowNanos - cachedAtNanos >= lifetimeNanos;
    }

    long elapsedSeconds(long nowNanos) {
        long elapsedNanos = nowNanos - cachedAtNanos;
        if (elapsedNanos <= 0) {
            return 0;
        }
        return elapsedNanos / 1_000_000_000L;
    }

    long remainingTtl(long nowNanos) {
        return Math.max(minimumTtlSeconds - elapsedSeconds(nowNanos), 0);
    }
}
