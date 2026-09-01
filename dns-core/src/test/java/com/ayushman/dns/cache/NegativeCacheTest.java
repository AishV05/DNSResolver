package com.ayushman.dns.cache;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.ayushman.dns.protocol.DnsHeader;
import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsQuestion;

public class NegativeCacheTest {

    @Test
    void shouldStoreAndRetrieveNxDomain() {

        NegativeCache cache =
                new NegativeCache();

        DnsQuestion question =
                new DnsQuestion(
                        "does-not-exist.example",
                        1,
                        1
                );

        DnsMessage response =
                createResponse(
                        question,
                        3
                );

        NegativeCacheEntry entry =
                createEntry(
                        response,
                        300
                );

        cache.put(
                question,
                NegativeCacheType.NXDOMAIN,
                entry
        );

        NegativeCacheEntry cached =
                cache.get(
                        question,
                        NegativeCacheType.NXDOMAIN
                );

        assertNotNull(cached);

        assertSame(
                response,
                cached.response()
        );
    }

    @Test
    void shouldStoreAndRetrieveNoData() {

        NegativeCache cache =
                new NegativeCache();

        DnsQuestion question =
                new DnsQuestion(
                        "google.com",
                        33,
                        1
                );

        DnsMessage response =
                createResponse(
                        question,
                        0
                );

        NegativeCacheEntry entry =
                createEntry(
                        response,
                        60
                );

        cache.put(
                question,
                NegativeCacheType.NODATA,
                entry
        );

        NegativeCacheEntry cached =
                cache.get(
                        question,
                        NegativeCacheType.NODATA
                );

        assertNotNull(cached);

        assertSame(
                response,
                cached.response()
        );
    }

    @Test
    void shouldNotMixNxDomainAndNoData() {

        NegativeCache cache =
                new NegativeCache();

        DnsQuestion question =
                new DnsQuestion(
                        "example.com",
                        1,
                        1
                );

        DnsMessage nxDomainResponse =
                createResponse(
                        question,
                        3
                );

        DnsMessage noDataResponse =
                createResponse(
                        question,
                        0
                );

        NegativeCacheEntry nxDomainEntry =
                createEntry(
                        nxDomainResponse,
                        300
                );

        NegativeCacheEntry noDataEntry =
                createEntry(
                        noDataResponse,
                        300
                );

        cache.put(
                question,
                NegativeCacheType.NXDOMAIN,
                nxDomainEntry
        );

        cache.put(
                question,
                NegativeCacheType.NODATA,
                noDataEntry
        );

        NegativeCacheEntry cachedNxDomain =
                cache.get(
                        question,
                        NegativeCacheType.NXDOMAIN
                );

        NegativeCacheEntry cachedNoData =
                cache.get(
                        question,
                        NegativeCacheType.NODATA
                );

        assertNotNull(cachedNxDomain);
        assertNotNull(cachedNoData);

        assertEquals(
                3,
                cachedNxDomain.response()
                        .header()
                        .flags() & 0x000F
        );

        assertEquals(
                0,
                cachedNoData.response()
                        .header()
                        .flags() & 0x000F
        );
    }

    @Test
    void shouldKeepDifferentNoDataTypesSeparate() {

        NegativeCache cache =
                new NegativeCache();

        DnsQuestion srvQuestion =
                new DnsQuestion(
                        "google.com",
                        33,
                        1
                );

        DnsQuestion mxQuestion =
                new DnsQuestion(
                        "google.com",
                        15,
                        1
                );

        DnsMessage srvResponse =
                createResponse(
                        srvQuestion,
                        0
                );

        DnsMessage mxResponse =
                createResponse(
                        mxQuestion,
                        0
                );

        NegativeCacheEntry srvEntry =
                createEntry(
                        srvResponse,
                        60
                );

        NegativeCacheEntry mxEntry =
                createEntry(
                        mxResponse,
                        60
                );

        cache.put(
                srvQuestion,
                NegativeCacheType.NODATA,
                srvEntry
        );

        cache.put(
                mxQuestion,
                NegativeCacheType.NODATA,
                mxEntry
        );

        NegativeCacheEntry cachedSrv =
                cache.get(
                        srvQuestion,
                        NegativeCacheType.NODATA
                );

        NegativeCacheEntry cachedMx =
                cache.get(
                        mxQuestion,
                        NegativeCacheType.NODATA
                );

        assertNotNull(cachedSrv);
        assertNotNull(cachedMx);

        assertEquals(
                33,
                cachedSrv.response()
                        .questions()
                        .get(0)
                        .type()
        );

        assertEquals(
                15,
                cachedMx.response()
                        .questions()
                        .get(0)
                        .type()
        );
    }

    @Test
    void shouldExpireNegativeEntry() throws InterruptedException {

        NegativeCache cache =
                new NegativeCache();

        DnsQuestion question =
                new DnsQuestion(
                        "expired.example",
                        1,
                        1
                );

        DnsMessage response =
                createResponse(
                        question,
                        3
                );

        NegativeCacheEntry entry =
                createEntry(
                        response,
                        1
                );

        cache.put(
                question,
                NegativeCacheType.NXDOMAIN,
                entry
        );

        assertNotNull(
                cache.get(
                        question,
                        NegativeCacheType.NXDOMAIN
                )
        );

        Thread.sleep(1100);

        assertNull(
                cache.get(
                        question,
                        NegativeCacheType.NXDOMAIN
                )
        );
    }

    @Test
    void shouldReturnNullForUnknownEntry() {

        NegativeCache cache =
                new NegativeCache();

        DnsQuestion question =
                new DnsQuestion(
                        "unknown.example",
                        1,
                        1
                );

        assertNull(
                cache.get(
                        question,
                        NegativeCacheType.NXDOMAIN
                )
        );

        assertNull(
                cache.get(
                        question,
                        NegativeCacheType.NODATA
                )
        );
    }

    private NegativeCacheEntry createEntry(
            DnsMessage response,
            long ttlSeconds
    ) {

        long now =
                System.currentTimeMillis();

        long expiresAt =
                now + (ttlSeconds * 1000);

        return new NegativeCacheEntry(
                response,
                now,
                expiresAt
        );
    }

    private DnsMessage createResponse(
            DnsQuestion question,
            int rcode
    ) {

        int flags =
                0x8180 | rcode;

        DnsHeader header =
                new DnsHeader(
                        1234,
                        flags,
                        1,
                        0,
                        0,
                        0
                );

        return new DnsMessage(
                header,
                List.of(question),
                List.of(),
                List.of(),
                List.of()
        );
    }
}