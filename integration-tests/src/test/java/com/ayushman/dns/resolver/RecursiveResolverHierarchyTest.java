package com.ayushman.dns.resolver;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.Test;

import com.ayushman.dns.protocol.DnsHeader;
import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsQuestion;
import com.ayushman.dns.protocol.DnsRecord;
import com.ayushman.dns.testing.DeterministicDnsHierarchy;
import com.ayushman.dns.testing.DeterministicDnsHierarchy.Hop;

public class RecursiveResolverHierarchyTest {

    @Test
    void shouldTraverseDeterministicHierarchyWithoutNetwork()
            throws Exception {

        DnsQuestion question =
                new DnsQuestion(
                        DeterministicDnsHierarchy.QUERY_NAME,
                        1,
                        1
                );

        DnsMessage clientQuery =
                new DnsMessage(
                        new DnsHeader(
                                1801,
                                0x0100,
                                1,
                                0,
                                0,
                                0
                        ),
                        List.of(question),
                        List.of(),
                        List.of(),
                        List.of()
                );

        DeterministicDnsHierarchy hierarchy =
                new DeterministicDnsHierarchy();

        RecursiveResolver resolver =
                new RecursiveResolver(
                        hierarchy,
                        List.of(
                                DeterministicDnsHierarchy.ROOT_SERVER
                        )
                );

        DnsMessage response =
                resolver.resolve(clientQuery);

        assertEquals(1801, response.header().id());
        assertEquals(1, response.answers().size());

        DnsRecord answer =
                response.answers().get(0);

        assertEquals(
                DeterministicDnsHierarchy.QUERY_NAME,
                answer.name()
        );
        assertEquals(1, answer.type());
        assertEquals(1, answer.qclass());
        assertArrayEquals(
                new byte[] {
                        (byte) 192,
                        0,
                        2,
                        80
                },
                answer.rdata()
        );

        assertEquals(
                List.of(
                        new Hop(
                                DeterministicDnsHierarchy.ROOT_SERVER,
                                question
                        ),
                        new Hop(
                                DeterministicDnsHierarchy.TLD_SERVER,
                                question
                        ),
                        new Hop(
                                DeterministicDnsHierarchy.AUTHORITATIVE_SERVER,
                                question
                        )
                ),
                hierarchy.hops()
        );
    }
}
