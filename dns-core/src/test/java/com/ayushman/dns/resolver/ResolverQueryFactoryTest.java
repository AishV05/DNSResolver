package com.ayushman.dns.resolver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import org.junit.jupiter.api.Test;

import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsQuestion;
import com.ayushman.dns.protocol.EdnsInfo;

public class ResolverQueryFactoryTest {

    @Test
    void shouldAddEdnsZeroToUpstreamQuery() {

        DnsMessage query =
                ResolverQueryFactory.create(
                        new DnsQuestion(
                                "example.com",
                                1,
                                1
                        )
                );

        EdnsInfo edns = query.edns().orElseThrow();

        assertEquals(
                ResolverQueryFactory.UPSTREAM_UDP_PAYLOAD_SIZE,
                edns.udpPayloadSize()
        );
        assertEquals(0, edns.extendedRcode());
        assertEquals(0, edns.version());
        assertEquals(0, edns.flags());
        assertFalse(edns.dnssecOk());
        assertEquals(0, edns.options().length);
    }
}
