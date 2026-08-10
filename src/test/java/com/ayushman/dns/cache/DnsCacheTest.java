package com.ayushman.dns.cache;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.ayushman.dns.protocol.DnsHeader;
import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsQuestion;
import com.ayushman.dns.protocol.DnsRecord;

public class DnsCacheTest {

    @Test
    void shouldStoreAndRetrieveResponse() {

        DnsCache cache = new DnsCache();

        DnsQuestion question =
                new DnsQuestion(
                        "example.com",
                        1,
                        1
                );

        DnsMessage response =
                createResponse(question);

        cache.put(
                question,
                response,
                300
        );

        CachedDnsData cached =
                cache.get(question);

        assertNotNull(cached);

        assertEquals(
                "example.com",
                cached.questions().get(0).name()
        );

        assertEquals(
                1,
                cached.answers().size()
        );
    }

    @Test
    void shouldReturnRemainingTtl() {

        DnsCache cache = new DnsCache();

        DnsQuestion question =
                new DnsQuestion(
                        "example.com",
                        1,
                        1
                );

        DnsMessage response =
                createResponse(question);

        cache.put(
                question,
                response,
                300
        );

        long remainingTtl =
                cache.remainingTtl(question);

        assertTrue(
                remainingTtl > 0
        );

        assertTrue(
                remainingTtl <= 300
        );
    }

    @Test
    void shouldReturnNullForUnknownQuestion() {

        DnsCache cache = new DnsCache();

        DnsQuestion question =
                new DnsQuestion(
                        "unknown-example.com",
                        1,
                        1
                );

        CachedDnsData cached =
                cache.get(question);

        assertNull(cached);
    }

    @Test
    void shouldKeepDifferentQuestionsSeparate() {

        DnsCache cache = new DnsCache();

        DnsQuestion first =
                new DnsQuestion(
                        "example.com",
                        1,
                        1
                );

        DnsQuestion second =
                new DnsQuestion(
                        "example.org",
                        1,
                        1
                );

        DnsMessage firstResponse =
                createResponse(first);

        DnsMessage secondResponse =
                createResponse(second);

        cache.put(
                first,
                firstResponse,
                300
        );

        cache.put(
                second,
                secondResponse,
                300
        );

        CachedDnsData firstCached =
                cache.get(first);

        CachedDnsData secondCached =
                cache.get(second);

        assertNotNull(firstCached);
        assertNotNull(secondCached);

        assertEquals(
                "example.com",
                firstCached.questions().get(0).name()
        );

        assertEquals(
                "example.org",
                secondCached.questions().get(0).name()
        );
    }

    @Test
    void shouldExpireEntryAfterTtl() throws InterruptedException {

        DnsCache cache = new DnsCache();

        DnsQuestion question =
                new DnsQuestion(
                        "expired.example.com",
                        1,
                        1
                );

        DnsMessage response =
                createResponse(question);

        cache.put(
                question,
                response,
                1
        );

        assertNotNull(
                cache.get(question)
        );

        Thread.sleep(1100);

        assertNull(
                cache.get(question)
        );
    }

    private DnsMessage createResponse(
            DnsQuestion question
    ) {

        DnsHeader header =
                new DnsHeader(
                        1234,
                        0x8180,
                        1,
                        1,
                        0,
                        0
                );

        DnsRecord answer =
                new DnsRecord(
                        question.name(),
                        question.type(),
                        question.qclass(),
                        300,
                        new byte[] {
                                1, 2, 3, 4
                        }
                );

        return new DnsMessage(
                header,
                List.of(question),
                List.of(answer),
                List.of(),
                List.of()
        );
    }
}