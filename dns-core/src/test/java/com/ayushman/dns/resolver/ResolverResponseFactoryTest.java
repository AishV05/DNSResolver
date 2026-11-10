package com.ayushman.dns.resolver;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.ayushman.dns.cache.CachedDnsData;
import com.ayushman.dns.protocol.DnsHeader;
import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsQuestion;
import com.ayushman.dns.protocol.DnsRecord;

class ResolverResponseFactoryTest {

    private static final DnsQuestion QUESTION =
            new DnsQuestion("example.com", 1, 1);

    @Test
    void shouldBuildClientFlagsWithoutTrustingUpstreamAssertions() {
        DnsMessage clientQuery = message(
                new DnsHeader(0x1234, 0x0110, 1, 0, 0, 0),
                List.of(),
                List.of(),
                List.of()
        );
        DnsMessage upstreamResponse = message(
                new DnsHeader(
                        0xABCD,
                        0x8000 | 0x0400 | 0x0200 | 0x0080
                                | 0x0020 | 0x0010 | 0x0003,
                        99,
                        99,
                        99,
                        99
                ),
                new DnsQuestion("EXAMPLE.COM", 1, 1),
                List.of(record(1)),
                List.of(record(2)),
                List.of(record(3))
        );

        DnsMessage response =
                ResolverResponseFactory.fromUpstream(
                        clientQuery,
                        upstreamResponse
                );

        assertEquals(0x1234, response.header().id());
        assertEquals(0x8193, response.header().flags());
        assertEquals(1, response.header().qdCount());
        assertEquals(1, response.header().anCount());
        assertEquals(1, response.header().nsCount());
        assertEquals(1, response.header().arCount());
        assertEquals(QUESTION, response.questions().get(0));
    }

    @Test
    void shouldPreserveClientOpcodeButNotUpstreamOpcode() {
        DnsMessage clientQuery = message(
                new DnsHeader(1, 0x0800 | 0x0100, 1, 0, 0, 0),
                List.of(),
                List.of(),
                List.of()
        );
        DnsMessage upstreamResponse = message(
                new DnsHeader(2, 0x8000 | 0x1000, 1, 0, 0, 0),
                List.of(),
                List.of(),
                List.of()
        );

        DnsMessage response =
                ResolverResponseFactory.fromUpstream(
                        clientQuery,
                        upstreamResponse
                );

        assertEquals(0x8980, response.header().flags());
    }

    @Test
    void shouldUseSafeFlagsForCachedResponses() {
        DnsMessage clientQuery = message(
                new DnsHeader(7, 0x0110, 1, 0, 0, 0),
                List.of(),
                List.of(),
                List.of()
        );
        CachedDnsData cached =
                new CachedDnsData(
                        List.of(QUESTION),
                        List.of(record(1)),
                        List.of(),
                        List.of()
                );

        DnsMessage response =
                ResolverResponseFactory.create(clientQuery, cached, 30);

        assertEquals(0x8190, response.header().flags());
    }

    private static DnsMessage message(
            DnsHeader header,
            List<DnsRecord> answers,
            List<DnsRecord> authorities,
            List<DnsRecord> additionals
    ) {
        return message(
                header,
                QUESTION,
                answers,
                authorities,
                additionals
        );
    }

    private static DnsMessage message(
            DnsHeader header,
            DnsQuestion question,
            List<DnsRecord> answers,
            List<DnsRecord> authorities,
            List<DnsRecord> additionals
    ) {
        return new DnsMessage(
                header,
                List.of(question),
                answers,
                authorities,
                additionals
        );
    }

    private static DnsRecord record(int lastAddressOctet) {
        return new DnsRecord(
                "example.com",
                1,
                1,
                60,
                new byte[]{(byte) 192, 0, 2, (byte) lastAddressOctet}
        );
    }
}
