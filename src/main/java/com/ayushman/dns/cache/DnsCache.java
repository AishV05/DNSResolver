package com.ayushman.dns.cache;

import java.util.concurrent.ConcurrentHashMap;

import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsQuestion;

public class DnsCache {

    private final ConcurrentHashMap<
            CacheKey,
            CacheEntry
    > entries = new ConcurrentHashMap<>();

    public DnsMessage get(
            DnsQuestion question
    ) {

        CacheKey key =
                CacheKey.from(question);

        CacheEntry entry =
                entries.get(key);

        if (entry == null) {
            return null;
        }

        if (entry.expired()) {

            entries.remove(key);

            return null;
        }

        return entry.response();
    }

    public void put(
            DnsQuestion question,
            DnsMessage response,
            long ttlSeconds
    ) {

        CacheKey key =
                CacheKey.from(question);

        long expiresAt =
                System.currentTimeMillis()
                        + ttlSeconds * 1000;

        entries.put(
                key,
                new CacheEntry(
                        response,
                        expiresAt
                )
        );
    }

    public int size() {
        return entries.size();
    }
}