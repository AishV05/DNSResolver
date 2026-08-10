package com.ayushman.dns.resolver;

import com.ayushman.dns.cache.CachedDnsData;
import com.ayushman.dns.protocol.DnsHeader;
import com.ayushman.dns.protocol.DnsMessage;

public final class ResolverResponseFactory {

    private ResolverResponseFactory() {
    }

    public static DnsMessage create(
            DnsMessage clientQuery,
            CachedDnsData cached,
            long remainingTtl
    ) {

        int flags = buildResponseFlags(clientQuery);

        DnsHeader header =
                new DnsHeader(
                        clientQuery.header().id(),
                        flags,
                        cached.questions().size(),
                        cached.answers().size(),
                        cached.authorities().size(),
                        cached.additionals().size()
                );

        return new DnsMessage(
                header,
                cached.questions(),
                DnsRecordCloner.cloneRecords(
                cached.answers(),
                remainingTtl
                ),
                DnsRecordCloner.cloneRecords(
                cached.authorities(),
                remainingTtl
        ),
                DnsRecordCloner.cloneRecords(
                cached.additionals(),
                remainingTtl
        )
        );
    }

    /**
     * Builds response flags for a recursive resolver.
     */
    private static int buildResponseFlags(
            DnsMessage clientQuery
    ) {

        int requestFlags = clientQuery.header().flags();

        // Preserve RD (Recursion Desired)
        int rd = requestFlags & 0x0100;

        // QR = Response
        int qr = 0x8000;

        // RA = Recursion Available
        int ra = 0x0080;

        return qr | rd | ra;
    }

    public static DnsMessage fromUpstream(
        DnsMessage clientQuery,
        DnsMessage upstreamResponse
) {

    DnsHeader upstreamHeader =
            upstreamResponse.header();

    DnsHeader clientHeader =
            new DnsHeader(
                    clientQuery.header().id(),
                    upstreamHeader.flags(),
                    upstreamHeader.qdCount(),
                    upstreamHeader.anCount(),
                    upstreamHeader.nsCount(),
                    upstreamHeader.arCount()
            );

    return new DnsMessage(
            clientHeader,
            upstreamResponse.questions(),
            upstreamResponse.answers(),
            upstreamResponse.authorities(),
            upstreamResponse.additionals()
    );
}
}