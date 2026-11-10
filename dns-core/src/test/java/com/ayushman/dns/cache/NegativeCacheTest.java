package com.ayushman.dns.cache;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;

import com.ayushman.dns.protocol.DnsHeader;
import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsNameCodec;
import com.ayushman.dns.protocol.DnsQuestion;
import com.ayushman.dns.protocol.DnsRecord;
import com.ayushman.dns.resolver.ResolverObserver;

class NegativeCacheTest {

    @Test
    void shouldUseCanonicalNameAndShareNxDomainAcrossTypes() {
        MutableTicker ticker = new MutableTicker();
        NegativeCache cache = new NegativeCache(8, 300, ticker::read);
        DnsQuestion stored = question("Missing.Example", 1);

        assertTrue(cache.put(
                stored,
                NegativeCacheType.NXDOMAIN,
                negativeResponse(stored, 3, 120, 90)
        ));

        assertNotNull(cache.get(
                question("missing.example.", 15),
                NegativeCacheType.NXDOMAIN
        ));
    }

    @Test
    void shouldKeepNoDataTypesSeparate() {
        MutableTicker ticker = new MutableTicker();
        NegativeCache cache = new NegativeCache(8, 300, ticker::read);
        DnsQuestion srv = question("service.example", 33);
        cache.put(
                srv,
                NegativeCacheType.NODATA,
                negativeResponse(srv, 0, 120, 90)
        );

        assertNotNull(cache.get(srv, NegativeCacheType.NODATA));
        assertNull(cache.get(
                question("service.example", 15),
                NegativeCacheType.NODATA
        ));
    }

    @Test
    void shouldCapAndAgeSoaTtlUsingMonotonicTime() {
        MutableTicker ticker = new MutableTicker();
        NegativeCache cache = new NegativeCache(8, 60, ticker::read);
        DnsQuestion question = question("missing.example", 1);

        cache.put(
                question,
                NegativeCacheType.NXDOMAIN,
                negativeResponse(question, 3, 120, 90)
        );
        ticker.advanceSeconds(15);
        NegativeCacheEntry hit = cache.get(
                question,
                NegativeCacheType.NXDOMAIN
        );

        assertNotNull(hit);
        assertEquals(45, hit.remainingTtl());
        assertEquals(45, hit.response().authorities().get(0).ttl());

        ticker.advanceSeconds(45);
        assertNull(cache.get(question, NegativeCacheType.NXDOMAIN));
    }

    @Test
    void shouldRejectMissingOrZeroNegativeProof() {
        MutableTicker ticker = new MutableTicker();
        NegativeCache cache = new NegativeCache(8, 300, ticker::read);
        DnsQuestion question = question("missing.example", 1);
        DnsMessage withoutSoa = new DnsMessage(
                new DnsHeader(1, 0x8403, 1, 0, 0, 0),
                List.of(question),
                List.of(),
                List.of(),
                List.of()
        );

        assertFalse(cache.put(
                question,
                NegativeCacheType.NXDOMAIN,
                withoutSoa
        ));
        assertFalse(cache.put(
                question,
                NegativeCacheType.NXDOMAIN,
                negativeResponse(question, 3, 120, 0)
        ));
        assertEquals(0, cache.size());
    }

    @Test
    void shouldEvictLeastRecentlyUsedEntry() {
        MutableTicker ticker = new MutableTicker();
        NegativeCache cache = new NegativeCache(2, 300, ticker::read);
        DnsQuestion first = question("first.example", 1);
        DnsQuestion second = question("second.example", 1);
        DnsQuestion third = question("third.example", 1);

        cache.put(first, NegativeCacheType.NXDOMAIN,
                negativeResponse(first, 3, 100, 100));
        cache.put(second, NegativeCacheType.NXDOMAIN,
                negativeResponse(second, 3, 100, 100));
        assertNotNull(cache.get(first, NegativeCacheType.NXDOMAIN));
        cache.put(third, NegativeCacheType.NXDOMAIN,
                negativeResponse(third, 3, 100, 100));

        assertNotNull(cache.get(first, NegativeCacheType.NXDOMAIN));
        assertNull(cache.get(second, NegativeCacheType.NXDOMAIN));
        assertNotNull(cache.get(third, NegativeCacheType.NXDOMAIN));
    }

    @Test
    void shouldSelectClosestEnclosingAuthoritativeSoa() {
        MutableTicker ticker = new MutableTicker();
        NegativeCache cache = new NegativeCache(8, 300, ticker::read);
        DnsQuestion question = question("host.sub.example", 1);
        DnsRecord broad = soa("example", 200, 180);
        DnsRecord closest = soa("sub.example", 40, 30);
        DnsMessage response = negativeResponse(
                question,
                3,
                List.of(broad, closest),
                0x8403
        );

        assertTrue(cache.put(
                question,
                NegativeCacheType.NXDOMAIN,
                response
        ));
        NegativeCacheEntry hit = cache.get(
                question,
                NegativeCacheType.NXDOMAIN
        );

        assertNotNull(hit);
        assertEquals(30, hit.remainingTtl());
        assertEquals("sub.example", hit.response().authorities().get(0).name());
    }

    @Test
    void shouldRejectNonAuthoritativeNegativeResponses() {
        MutableTicker ticker = new MutableTicker();
        NegativeCache cache = new NegativeCache(8, 300, ticker::read);
        DnsQuestion question = question("missing.example", 1);
        DnsMessage nonAuthoritative = negativeResponse(
                question,
                3,
                List.of(soa("example", 120, 90)),
                0x8003
        );

        assertFalse(cache.put(
                question,
                NegativeCacheType.NXDOMAIN,
                nonAuthoritative
        ));
        assertEquals(0, cache.size());
    }

    @Test
    void shouldSurviveMonotonicTickerWraparound() {
        MutableTicker ticker = new MutableTicker();
        ticker.set(Long.MAX_VALUE - 5_000_000_000L);
        NegativeCache cache = new NegativeCache(8, 300, ticker::read);
        DnsQuestion question = question("missing.example", 1);

        assertTrue(cache.put(
                question,
                NegativeCacheType.NXDOMAIN,
                negativeResponse(question, 3, 10, 10)
        ));
        ticker.advanceSeconds(6);
        NegativeCacheEntry hit = cache.get(
                question,
                NegativeCacheType.NXDOMAIN
        );
        assertNotNull(hit);
        assertEquals(4, hit.remainingTtl());
        assertEquals(4, hit.response().authorities().get(0).ttl());
        ticker.advanceSeconds(4);
        assertNull(cache.get(question, NegativeCacheType.NXDOMAIN));
    }

    @Test
    void shouldReportFixedCacheOutcomesAndCapacityEvictions() {
        MutableTicker ticker = new MutableTicker();
        RecordingObserver observer = new RecordingObserver();
        NegativeCache cache = new NegativeCache(
                1,
                300,
                ticker::read,
                observer
        );
        DnsQuestion first = question("first.example", 1);
        DnsQuestion second = question("second.example", 1);

        assertNull(cache.get(first, NegativeCacheType.NXDOMAIN));
        cache.put(first, NegativeCacheType.NXDOMAIN,
                negativeResponse(first, 3, 60, 60));
        assertNotNull(cache.get(first, NegativeCacheType.NXDOMAIN));
        cache.put(second, NegativeCacheType.NXDOMAIN,
                negativeResponse(second, 3, 60, 60));

        assertEquals(1, observer.hits);
        assertEquals(1, observer.misses);
        assertEquals(1, observer.evictions);
    }

    private DnsQuestion question(String name, int type) {
        return new DnsQuestion(name, type, 1);
    }

    private DnsMessage negativeResponse(
            DnsQuestion question,
            int rcode,
            long soaTtl,
            long minimum
    ) {
        DnsRecord soa = soa("example", soaTtl, minimum);
        return negativeResponse(
                question,
                rcode,
                List.of(soa),
                0x8400 | rcode
        );
    }

    private DnsMessage negativeResponse(
            DnsQuestion question,
            int rcode,
            List<DnsRecord> authorities,
            int flags
    ) {
        return new DnsMessage(
                new DnsHeader(
                        1,
                        flags,
                        1,
                        0,
                        authorities.size(),
                        0
                ),
                List.of(question),
                List.of(),
                authorities,
                List.of()
        );
    }

    private DnsRecord soa(String owner, long ttl, long minimum) {
        return new DnsRecord(owner, 6, 1, ttl, soaData(minimum));
    }

    private byte[] soaData(long minimum) {
        ByteBuffer buffer = ByteBuffer.allocate(512);
        DnsNameCodec.encode("ns.example", buffer);
        DnsNameCodec.encode("hostmaster.example", buffer);
        buffer.putInt(1);
        buffer.putInt(2);
        buffer.putInt(3);
        buffer.putInt(4);
        buffer.putInt((int) minimum);
        byte[] data = new byte[buffer.position()];
        buffer.flip();
        buffer.get(data);
        return data;
    }

    private static final class MutableTicker {
        private final AtomicLong nanos = new AtomicLong();

        long read() {
            return nanos.get();
        }

        void advanceSeconds(long seconds) {
            nanos.addAndGet(seconds * 1_000_000_000L);
        }

        void set(long value) {
            nanos.set(value);
        }
    }

    private static final class RecordingObserver implements ResolverObserver {
        private int hits;
        private int misses;
        private int evictions;

        @Override
        public void cacheLookup(CacheKind cache, boolean hit) {
            assertEquals(CacheKind.NEGATIVE, cache);
            if (hit) {
                hits++;
            } else {
                misses++;
            }
        }

        @Override
        public void cacheEviction(CacheKind cache) {
            assertEquals(CacheKind.NEGATIVE, cache);
            evictions++;
        }
    }
}
