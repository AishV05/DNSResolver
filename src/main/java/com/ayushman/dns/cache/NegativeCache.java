package com.ayushman.dns.cache;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import com.ayushman.dns.protocol.DnsQuestion;

public class NegativeCache {

    private final ConcurrentMap<
            NegativeCacheKey,
            NegativeCacheEntry
            > entries =
            new ConcurrentHashMap<>();

    public NegativeCacheEntry get(
            DnsQuestion question,
            NegativeCacheType type
    ) {

        NegativeCacheKey key;

        if (type == NegativeCacheType.NXDOMAIN) {

            key = new NegativeCacheKey(
                    question.name(),
                    0,
                    question.qclass(),
                    type
            );

        } else {

            key = new NegativeCacheKey(
                    question.name(),
                    question.type(),
                    question.qclass(),
                    type
            );
        }

        NegativeCacheEntry entry =
                entries.get(key);

        if (entry == null) {
            return null;
        }

        if (entry.expired()) {

            entries.remove(key, entry);

            return null;
        }

        return entry;
    }

    public void put(
            DnsQuestion question,
            NegativeCacheType type,
            NegativeCacheEntry entry
    ) {

        NegativeCacheKey key;

        if (type == NegativeCacheType.NXDOMAIN) {

            key = new NegativeCacheKey(
                    question.name(),
                    0,
                    question.qclass(),
                    type
            );

        } else {

            key = new NegativeCacheKey(
                    question.name(),
                    question.type(),
                    question.qclass(),
                    type
            );
        }

        entries.put(key, entry);
    }
}