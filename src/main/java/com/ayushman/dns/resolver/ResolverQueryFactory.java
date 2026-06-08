package com.ayushman.dns.resolver;

import java.util.List;

import com.ayushman.dns.protocol.DnsHeader;
import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsQuestion;

public final class ResolverQueryFactory {

    private ResolverQueryFactory() {}

    public static DnsMessage create(
            DnsQuestion question
    ) {

        DnsHeader header =
                new DnsHeader(
                        (int)(Math.random() * 65535),
                        0x0100,
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