package com.ayushman.dns.cache;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.LongSupplier;

import com.ayushman.dns.protocol.DnsHeader;
import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsQuestion;
import com.ayushman.dns.protocol.DnsRecord;
import com.ayushman.dns.resolver.ResolverObserver;

/** Thread-safe, bounded RFC 2308 negative cache. */
public final class NegativeCache {

    private static final int TYPE_SOA = 6;
    private static final int RCODE_MASK = 0x000F;
    private static final int AUTHORITATIVE_ANSWER_FLAG = 0x0400;

    private final int maximumEntries;
    private final long maximumTtlSeconds;
    private final LongSupplier ticker;
    private final ResolverObserver observer;
    private final LinkedHashMap<NegativeCacheKey, StoredEntry> entries =
            new LinkedHashMap<>(16, 0.75f, true);

    public NegativeCache() {
        this(
                ResolverCacheConfig.DEFAULT_NEGATIVE_MAX_ENTRIES,
                ResolverCacheConfig.DEFAULT_NEGATIVE_MAX_TTL_SECONDS,
                System::nanoTime,
                ResolverObserver.NOOP
        );
    }

    public NegativeCache(
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

    public NegativeCache(
            int maximumEntries,
            long maximumTtlSeconds,
            LongSupplier ticker,
            ResolverObserver observer
    ) {
        if (maximumEntries <= 0 || maximumTtlSeconds <= 0
                || ticker == null || observer == null) {
            throw new IllegalArgumentException(
                    "negative cache bounds and ticker must be valid"
            );
        }
        this.maximumEntries = maximumEntries;
        this.maximumTtlSeconds = maximumTtlSeconds;
        this.ticker = ticker;
        this.observer = observer;
    }

    public synchronized NegativeCacheEntry get(
            DnsQuestion question,
            NegativeCacheType type
    ) {
        NegativeCacheKey key = key(question, type);
        StoredEntry stored = entries.get(key);
        if (stored == null) {
            observer.cacheLookup(ResolverObserver.CacheKind.NEGATIVE, false);
            return null;
        }

        long now = ticker.getAsLong();
        if (now - stored.cachedAtNanos() >= stored.lifetimeNanos()) {
            entries.remove(key);
            observer.cacheLookup(ResolverObserver.CacheKind.NEGATIVE, false);
            return null;
        }

        long elapsedNanos = now - stored.cachedAtNanos();
        long elapsed = elapsedNanos <= 0
                ? 0
                : elapsedNanos / 1_000_000_000L;
        long remaining = Math.max(stored.ttlSeconds() - elapsed, 0);
        DnsMessage aged = ageNegativeResponse(stored.response(), remaining);

        observer.cacheLookup(ResolverObserver.CacheKind.NEGATIVE, true);
        return new NegativeCacheEntry(aged, remaining);
    }

    /** Stores only a validated SOA-backed NXDOMAIN or NODATA outcome. */
    public synchronized boolean put(
            DnsQuestion question,
            NegativeCacheType type,
            DnsMessage response
    ) {
        if (question == null || type == null || response == null
                || !response.answers().isEmpty()
                || (response.header().flags()
                        & AUTHORITATIVE_ANSWER_FLAG) == 0) {
            return false;
        }

        int rcode = response.header().flags() & RCODE_MASK;
        if ((type == NegativeCacheType.NXDOMAIN && rcode != 3)
                || (type == NegativeCacheType.NODATA && rcode != 0)) {
            return false;
        }

        DnsRecord soa = findSoa(response, question);
        if (soa == null) {
            return false;
        }
        long ttl = Math.min(
                SoaRecordUtil.negativeTtl(soa),
                maximumTtlSeconds
        );
        if (ttl <= 0) {
            return false;
        }

        DnsMessage normalized = negativeResponse(response, soa, ttl);
        store(key(question, type), normalized, ttl);
        return true;
    }

    /**
     * Legacy insertion shape retained for source compatibility. The entry is
     * still revalidated and its remaining wall-clock lifetime caps the SOA
     * TTL before it reaches the bounded cache.
     */
    @Deprecated(forRemoval = false)
    public synchronized void put(
            DnsQuestion question,
            NegativeCacheType type,
            NegativeCacheEntry entry
    ) {
        if (entry == null || entry.expired()) {
            return;
        }
        long remaining = entry.remainingTtl();
        if (remaining <= 0) {
            return;
        }
        DnsMessage source = entry.response();
        List<DnsRecord> boundedAuthorities = source.authorities().stream()
                .map(record -> CacheRecordSupport.copyWithTtl(
                        record,
                        Math.min(record.ttl(), remaining)
                ))
                .toList();
        put(
                question,
                type,
                new DnsMessage(
                        source.header(),
                        source.questions(),
                        source.answers(),
                        boundedAuthorities,
                        source.additionals(),
                        source.edns().orElse(null)
                )
        );
    }

    public synchronized int size() {
        return entries.size();
    }

    public synchronized void clear() {
        entries.clear();
    }

    public synchronized void invalidate(
            DnsQuestion question,
            NegativeCacheType type
    ) {
        entries.remove(key(question, type));
    }

    public synchronized void invalidateName(DnsQuestion question) {
        CanonicalDnsName name = CanonicalDnsName.from(question.name());
        int qclass = question.qclass();
        entries.keySet().removeIf(key -> key.qclass() == qclass
                && key.name().equals(name));
    }

    private void store(
            NegativeCacheKey key,
            DnsMessage response,
            long ttl
    ) {
        if (!entries.containsKey(key) && entries.size() >= maximumEntries) {
            Map.Entry<NegativeCacheKey, StoredEntry> eldest =
                    entries.entrySet().iterator().next();
            entries.remove(eldest.getKey());
            observer.cacheEviction(ResolverObserver.CacheKind.NEGATIVE);
        }
        long now = ticker.getAsLong();
        entries.put(
                key,
                new StoredEntry(
                        response,
                        now,
                        CacheRecordSupport.durationNanos(ttl),
                        ttl
                )
        );
    }

    private NegativeCacheKey key(
            DnsQuestion question,
            NegativeCacheType type
    ) {
        if (question == null || type == null) {
            throw new IllegalArgumentException(
                    "negative cache question and type must not be null"
            );
        }
        return new NegativeCacheKey(
                CanonicalDnsName.from(question.name()),
                type == NegativeCacheType.NXDOMAIN ? 0 : question.type(),
                question.qclass(),
                type
        );
    }

    private DnsRecord findSoa(
            DnsMessage response,
            DnsQuestion question
    ) {
        CanonicalDnsName questionName;
        try {
            questionName = CanonicalDnsName.from(question.name());
        } catch (IllegalArgumentException malformedQuestion) {
            return null;
        }
        DnsRecord selected = null;
        CanonicalDnsName selectedOwner = null;
        for (DnsRecord authority : response.authorities()) {
            if (authority.type() != TYPE_SOA
                    || authority.qclass() != question.qclass()) {
                continue;
            }
            try {
                CanonicalDnsName owner = CanonicalDnsName.from(
                        authority.name()
                );
                if (questionName.isAtOrBelow(owner)
                        && (selectedOwner == null
                                || owner.isAtOrBelow(selectedOwner))) {
                    selected = authority;
                    selectedOwner = owner;
                }
            } catch (IllegalArgumentException malformedOwner) {
                return null;
            }
        }
        return selected;
    }

    private DnsMessage negativeResponse(
            DnsMessage source,
            DnsRecord soa,
            long ttl
    ) {
        DnsRecord normalizedSoa = CacheRecordSupport.copyWithTtl(soa, ttl);
        DnsHeader header = new DnsHeader(
                source.header().id(),
                source.header().flags(),
                source.questions().size(),
                0,
                1,
                0
        );
        return new DnsMessage(
                header,
                source.questions(),
                List.of(),
                List.of(normalizedSoa),
                List.of()
        );
    }

    private DnsMessage ageNegativeResponse(
            DnsMessage source,
            long remainingTtl
    ) {
        List<DnsRecord> authorities = source.authorities().stream()
                .map(record -> CacheRecordSupport.copyWithTtl(
                        record,
                        remainingTtl
                ))
                .toList();
        return new DnsMessage(
                source.header(),
                source.questions(),
                List.of(),
                authorities,
                List.of()
        );
    }

    private record StoredEntry(
            DnsMessage response,
            long cachedAtNanos,
            long lifetimeNanos,
            long ttlSeconds
    ) {
    }
}
