package com.ayushman.dns.resolver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

import com.ayushman.dns.protocol.DnsHeader;
import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsQuestion;

class DnsResolverTest {

    @Test
    void supportsFrameworkFreeDecoratorComposition()
            throws Exception {
        AtomicInteger delegateCalls = new AtomicInteger();
        DnsResolver delegate = query -> {
            delegateCalls.incrementAndGet();
            return query;
        };
        DnsResolver decorator = delegate::resolve;
        DnsMessage query = new DnsMessage(
                new DnsHeader(123, 0x0100, 1, 0, 0, 0),
                List.of(new DnsQuestion("example.com", 1, 1)),
                List.of(),
                List.of(),
                List.of()
        );

        assertSame(query, decorator.resolve(query));
        assertEquals(1, delegateCalls.get());
    }
}
