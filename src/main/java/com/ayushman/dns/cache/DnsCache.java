package com.ayushman.dns.cache;

import java.util.concurrent.ConcurrentHashMap;

import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsQuestion;

public class DnsCache {

    private final ConcurrentHashMap<CacheKey, CacheEntry> entries =
            new ConcurrentHashMap<>();

    public CachedDnsData get(DnsQuestion question) {

        CacheKey key = CacheKey.from(question);

        CacheEntry entry = entries.get(key);

        if (entry == null) {
            return null;
        }

        if (entry.expired()) {

            entries.remove(key);

            return null;
        }

        return entry.data();
    }

    public void put(
            DnsQuestion question,
            DnsMessage response,
            long ttlSeconds
    ) {

        CacheKey key = CacheKey.from(question);

        CachedDnsData data =
                new CachedDnsData(
                        response.questions(),
                        response.answers(),
                        response.authorities(),
                        response.additionals()
                );

        long now = System.currentTimeMillis();

        long expiresAt =
                now + ttlSeconds * 1000;

        entries.put(
                key,
                new CacheEntry(
                        data,
                        now,
                        expiresAt,
                        ttlSeconds
                )
        );
    }
    public int size() {
        return entries.size();
    }

    public void clear() {
        entries.clear();
    }

    public long remainingTtl(DnsQuestion question) {

    CacheKey key = CacheKey.from(question);

    CacheEntry entry = entries.get(key);

    if (entry == null) {
        return 0;
    }

    if (entry.expired()) {

        entries.remove(key);

        return 0;
    }

    return entry.remainingTtl();
}
}