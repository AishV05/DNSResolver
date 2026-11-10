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

class DnsCacheTest {

    @Test
    void shouldCanonicalizeCaseAndTerminalRootLabel() {
        MutableTicker ticker = new MutableTicker();
        DnsCache cache = new DnsCache(8, 300, ticker::read);
        DnsQuestion stored = question("Example.COM");

        assertTrue(cache.put(stored, response(stored, List.of(
                record("Example.COM", 1, 120, new byte[] {1, 2, 3, 4})
        ))));

        assertNotNull(cache.get(question("example.com.")));
    }

    @Test
    void shouldKeepEscapedDotInsideOneLabelDistinct() {
        MutableTicker ticker = new MutableTicker();
        DnsCache cache = new DnsCache(8, 300, ticker::read);
        DnsQuestion oneLabel = question("a\\.b.example");

        cache.put(oneLabel, response(oneLabel, List.of(
                record(oneLabel.name(), 1, 120, new byte[] {1, 2, 3, 4})
        )));

        assertNotNull(cache.get(question("A\\.B.EXAMPLE.")));
        assertNull(cache.get(question("a.b.example")));
    }

    @Test
    void shouldNormalizeAndAgeEachRrsetIndependently() {
        MutableTicker ticker = new MutableTicker();
        DnsCache cache = new DnsCache(8, 60, ticker::read);
        DnsQuestion question = question("alias.example");
        List<DnsRecord> answers = List.of(
                record("alias.example", 5, 30, nameData("target.example")),
                record("target.example", 1, 120, new byte[] {1, 2, 3, 4}),
                record("TARGET.EXAMPLE.", 1, 90, new byte[] {5, 6, 7, 8})
        );

        assertTrue(cache.put(question, response(question, answers)));
        ticker.advanceSeconds(10);
        CachedDnsData hit = cache.get(question);

        assertNotNull(hit);
        assertEquals(20, hit.answers().get(0).ttl());
        assertEquals(50, hit.answers().get(1).ttl());
        assertEquals(50, hit.answers().get(2).ttl());

        ticker.advanceSeconds(20);
        assertNull(cache.get(question));
    }

    @Test
    void shouldEvictLeastRecentlyUsedEntry() {
        MutableTicker ticker = new MutableTicker();
        DnsCache cache = new DnsCache(2, 300, ticker::read);
        DnsQuestion first = question("first.example");
        DnsQuestion second = question("second.example");
        DnsQuestion third = question("third.example");

        cache.put(first, addressResponse(first, 100));
        cache.put(second, addressResponse(second, 100));
        assertNotNull(cache.get(first));
        cache.put(third, addressResponse(third, 100));

        assertNotNull(cache.get(first));
        assertNull(cache.get(second));
        assertNotNull(cache.get(third));
        assertEquals(2, cache.size());
    }

    @Test
    void shouldRejectZeroAndHighBitTtlWithoutEvictingValidData() {
        MutableTicker ticker = new MutableTicker();
        DnsCache cache = new DnsCache(1, 300, ticker::read);
        DnsQuestion valid = question("valid.example");
        DnsQuestion zero = question("zero.example");
        DnsQuestion highBit = question("high.example");
        cache.put(valid, addressResponse(valid, 100));

        assertFalse(cache.put(zero, addressResponse(zero, 0)));
        assertFalse(cache.put(highBit, addressResponse(highBit, 0x8000_0000L)));

        assertNotNull(cache.get(valid));
        assertEquals(1, cache.size());
    }

    @Test
    void shouldSurviveMonotonicTickerWraparound() {
        MutableTicker ticker = new MutableTicker();
        ticker.set(Long.MAX_VALUE - 5_000_000_000L);
        DnsCache cache = new DnsCache(1, 300, ticker::read);
        DnsQuestion question = question("wrap.example");

        assertTrue(cache.put(question, addressResponse(question, 10)));
        ticker.advanceSeconds(6);
        CachedDnsData hit = cache.get(question);
        assertNotNull(hit);
        assertEquals(4, hit.answers().get(0).ttl());
        ticker.advanceSeconds(4);
        assertNull(cache.get(question));
    }

    @Test
    void shouldReportFixedCacheOutcomesAndCapacityEvictions() {
        MutableTicker ticker = new MutableTicker();
        RecordingObserver observer = new RecordingObserver();
        DnsCache cache = new DnsCache(1, 300, ticker::read, observer);
        DnsQuestion first = question("first.example");
        DnsQuestion second = question("second.example");

        assertNull(cache.get(first));
        cache.put(first, addressResponse(first, 60));
        assertNotNull(cache.get(first));
        cache.put(second, addressResponse(second, 60));

        assertEquals(1, observer.hits);
        assertEquals(1, observer.misses);
        assertEquals(1, observer.evictions);
    }

    private DnsQuestion question(String name) {
        return new DnsQuestion(name, 1, 1);
    }

    private DnsMessage addressResponse(DnsQuestion question, long ttl) {
        return response(question, List.of(record(
                question.name(),
                1,
                ttl,
                new byte[] {1, 2, 3, 4}
        )));
    }

    private DnsMessage response(
            DnsQuestion question,
            List<DnsRecord> answers
    ) {
        return new DnsMessage(
                new DnsHeader(1, 0x8400, 1, answers.size(), 0, 0),
                List.of(question),
                answers,
                List.of(),
                List.of()
        );
    }

    private DnsRecord record(
            String name,
            int type,
            long ttl,
            byte[] rdata
    ) {
        return new DnsRecord(name, type, 1, ttl, rdata);
    }

    private byte[] nameData(String name) {
        ByteBuffer buffer = ByteBuffer.allocate(255);
        DnsNameCodec.encode(name, buffer);
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
            assertEquals(CacheKind.POSITIVE, cache);
            if (hit) {
                hits++;
            } else {
                misses++;
            }
        }

        @Override
        public void cacheEviction(CacheKind cache) {
            assertEquals(CacheKind.POSITIVE, cache);
            evictions++;
        }
    }
}
