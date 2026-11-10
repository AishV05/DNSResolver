package com.ayushman.dns.cache;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.LongSupplier;

import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsQuestion;
import com.ayushman.dns.resolver.ResolverObserver;

/** Thread-safe, bounded LRU cache for complete positive DNS outcomes. */
public final class DnsCache {

    private final int maximumEntries;
    private final long maximumTtlSeconds;
    private final LongSupplier ticker;
    private final ResolverObserver observer;
    private final LinkedHashMap<CacheKey, PositiveCacheEntry> entries =
            new LinkedHashMap<>(16, 0.75f, true);

    public DnsCache() {
        this(
                ResolverCacheConfig.DEFAULT_POSITIVE_MAX_ENTRIES,
                ResolverCacheConfig.DEFAULT_POSITIVE_MAX_TTL_SECONDS,
                System::nanoTime,
                ResolverObserver.NOOP
        );
    }

    public DnsCache(
            int maximumEntries,
            long maximumTtlSeconds,
            LongSupplier ticker
    ) {
        this(
                maximumEntries,
                maximumTtlSeconds,
                ticker,
                ResolverObserver.NOOP
        );
    }

    public DnsCache(
            int maximumEntries,
            long maximumTtlSeconds,
            LongSupplier ticker,
            ResolverObserver observer
    ) {
        if (maximumEntries <= 0 || maximumTtlSeconds <= 0
                || ticker == null || observer == null) {
            throw new IllegalArgumentException(
                    "positive cache bounds and ticker must be valid"
            );
        }
        this.maximumEntries = maximumEntries;
        this.maximumTtlSeconds = maximumTtlSeconds;
        this.ticker = ticker;
        this.observer = observer;
    }

    public synchronized CachedDnsData get(DnsQuestion question) {
        CacheKey key = CacheKey.from(question);
        PositiveCacheEntry entry = entries.get(key);
        if (entry == null) {
            observer.cacheLookup(ResolverObserver.CacheKind.POSITIVE, false);
            return null;
        }

        long now = ticker.getAsLong();
        if (entry.expired(now)) {
            entries.remove(key);
            observer.cacheLookup(ResolverObserver.CacheKind.POSITIVE, false);
            return null;
        }
        observer.cacheLookup(ResolverObserver.CacheKind.POSITIVE, true);
        return CacheRecordSupport.age(entry.data(), entry.elapsedSeconds(now));
    }

    public boolean put(DnsQuestion question, DnsMessage response) {
        return putWithMaximumTtl(question, response, maximumTtlSeconds);
    }

    /** Compatibility overload; the supplied TTL acts as an additional cap. */
    public boolean put(
            DnsQuestion question,
            DnsMessage response,
            long ttlSeconds
    ) {
        return putWithMaximumTtl(
                question,
                response,
                Math.min(maximumTtlSeconds, Math.max(ttlSeconds, 0))
        );
    }

    private synchronized boolean putWithMaximumTtl(
            DnsQuestion question,
            DnsMessage response,
            long ttlCap
    ) {
        if (question == null || response == null || ttlCap <= 0) {
            return false;
        }

        CachedDnsData data = CacheRecordSupport.normalizedPositive(
                response,
                ttlCap
        );
        if (data == null) {
            return false;
        }
        long minimumTtl = CacheRecordSupport.minimumTtl(data);
        if (minimumTtl <= 0) {
            return false;
        }

        CacheKey key = CacheKey.from(question);
        long now = ticker.getAsLong();
        if (!entries.containsKey(key) && entries.size() >= maximumEntries) {
            Map.Entry<CacheKey, PositiveCacheEntry> eldest =
                    entries.entrySet().iterator().next();
            entries.remove(eldest.getKey());
            observer.cacheEviction(ResolverObserver.CacheKind.POSITIVE);
        }
        entries.put(
                key,
                new PositiveCacheEntry(
                        data,
                        now,
                        CacheRecordSupport.durationNanos(minimumTtl),
                        minimumTtl
                )
        );
        return true;
    }

    public synchronized int size() {
        return entries.size();
    }

    public synchronized void clear() {
        entries.clear();
    }

    public synchronized void invalidate(DnsQuestion question) {
        entries.remove(CacheKey.from(question));
    }

    public synchronized void invalidateName(DnsQuestion question) {
        CanonicalDnsName name = CanonicalDnsName.from(question.name());
        int qclass = question.qclass();
        entries.keySet().removeIf(key -> key.qclass() == qclass
                && key.name().equals(name));
    }

    public synchronized long remainingTtl(DnsQuestion question) {
        CacheKey key = CacheKey.from(question);
        PositiveCacheEntry entry = entries.get(key);
        if (entry == null) {
            return 0;
        }
        long now = ticker.getAsLong();
        if (entry.expired(now)) {
            entries.remove(key);
            return 0;
        }
        return entry.remainingTtl(now);
    }
}
