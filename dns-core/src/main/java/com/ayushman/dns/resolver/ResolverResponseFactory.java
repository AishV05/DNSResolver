package com.ayushman.dns.resolver;

import com.ayushman.dns.cache.CachedDnsData;
import com.ayushman.dns.protocol.DnsHeader;
import com.ayushman.dns.protocol.DnsMessage;

public final class ResolverResponseFactory {

    private static final int QR = 0x8000;
    private static final int OPCODE_MASK = 0x7800;
    private static final int RD = 0x0100;
    private static final int RA = 0x0080;
    private static final int CD = 0x0010;
    private static final int RCODE_MASK = 0x000F;

    private ResolverResponseFactory() {
    }

    public static DnsMessage create(
            DnsMessage clientQuery,
            CachedDnsData cached
    ) {

        int flags = buildResponseFlags(clientQuery, 0);

        DnsHeader header =
                new DnsHeader(
                        clientQuery.header().id(),
                        flags,
                        clientQuery.questions().size(),
                        cached.answers().size(),
                        cached.authorities().size(),
                        cached.additionals().size()
                );

        return new DnsMessage(
                header,
                clientQuery.questions(),
                cached.answers(),
                cached.authorities(),
                cached.additionals()
        );
    }

    /**
     * Compatibility overload for callers with legacy single-TTL cache data.
     */
    public static DnsMessage create(
            DnsMessage clientQuery,
            CachedDnsData cached,
            long remainingTtl
    ) {
        CachedDnsData aged = new CachedDnsData(
                cached.questions(),
                DnsRecordCloner.cloneRecords(cached.answers(), remainingTtl),
                DnsRecordCloner.cloneRecords(
                        cached.authorities(),
                        remainingTtl
                ),
                DnsRecordCloner.cloneRecords(
                        cached.additionals(),
                        remainingTtl
                )
        );
        return create(clientQuery, aged);
    }

    /**
     * Builds response flags for a recursive resolver.
     */
    private static int buildResponseFlags(
            DnsMessage clientQuery,
            int responseCode
    ) {
        int requestFlags = clientQuery.header().flags();

        return QR
                | RA
                | (requestFlags & (OPCODE_MASK | RD | CD))
                | (responseCode & RCODE_MASK);
    }

    public static DnsMessage fromUpstream(
            DnsMessage clientQuery,
            DnsMessage upstreamResponse
    ) {
        DnsHeader upstreamHeader = upstreamResponse.header();

        DnsHeader clientHeader =
                new DnsHeader(
                        clientQuery.header().id(),
                        buildResponseFlags(
                                clientQuery,
                                upstreamHeader.flags()
                        ),
                        clientQuery.questions().size(),
                        upstreamResponse.answers().size(),
                        upstreamResponse.authorities().size(),
                        upstreamResponse.additionals().size()
                );

        return new DnsMessage(
                clientHeader,
                clientQuery.questions(),
                upstreamResponse.answers(),
                upstreamResponse.authorities(),
                upstreamResponse.additionals()
        );
    }
}
