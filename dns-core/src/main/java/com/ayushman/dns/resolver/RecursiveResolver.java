package com.ayushman.dns.resolver;

import java.util.List;

import com.ayushman.dns.cache.CachedDnsData;
import com.ayushman.dns.cache.DnsCache;
import com.ayushman.dns.cache.NegativeCache;
import com.ayushman.dns.cache.NegativeCacheEntry;
import com.ayushman.dns.cache.NegativeCacheType;
import com.ayushman.dns.cache.SoaRecordUtil;
import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsQuestion;
import com.ayushman.dns.protocol.DnsRecord;

public class RecursiveResolver {

    private final UpstreamDnsClient client;

    private final List<String> rootServers;

    private final DnsCache cache =
            new DnsCache();

    private final NegativeCache negativeCache =
            new NegativeCache();

    public RecursiveResolver() {
        this(
                new UpstreamDnsClient(),
                RootServers.ROOT_SERVERS
        );
    }

    public RecursiveResolver(
            UpstreamDnsClient client
    ) {

        this(
                client,
                RootServers.ROOT_SERVERS
        );
    }

    public RecursiveResolver(
            UpstreamDnsClient client,
            List<String> rootServers
    ) {

        if (client == null) {
            throw new IllegalArgumentException(
                    "client must not be null"
            );
        }

        if (rootServers == null || rootServers.isEmpty()) {
            throw new IllegalArgumentException(
                    "rootServers must not be empty"
            );
        }

        this.client = client;
        this.rootServers = List.copyOf(rootServers);
    }

    public DnsMessage resolve(DnsMessage clientQuery)
            throws Exception {

        DnsQuestion question =
                clientQuery.questions().get(0);

        NegativeCacheEntry negativeCached =
                negativeCache.get(
                        question,
                        NegativeCacheType.NXDOMAIN
                );

        if (negativeCached != null) {

            long remainingTtl =
                    negativeCached.remainingTtl();

            System.out.println(
                    "NEGATIVE CACHE HIT: "
                            + question.name()
                            + " NXDOMAIN"
                            + " (TTL="
                            + remainingTtl
                            + " seconds)"
            );

            return ResolverResponseFactory.fromUpstream(
                    clientQuery,
                    negativeCached.response()
            );
        }

        negativeCached =
                negativeCache.get(
                        question,
                        NegativeCacheType.NODATA
                );

        if (negativeCached != null) {

            long remainingTtl =
                    negativeCached.remainingTtl();

            System.out.println(
                    "NEGATIVE CACHE HIT: "
                            + question.name()
                            + " "
                            + question.type()
                            + " NODATA"
                            + " (TTL="
                            + remainingTtl
                            + " seconds)"
            );

            return ResolverResponseFactory.fromUpstream(
                    clientQuery,
                    negativeCached.response()
            );
        }

        CachedDnsData cached =
                cache.get(question);

        if (cached != null) {

            long remainingTtl =
                    cache.remainingTtl(question);

            System.out.println(
                    "CACHE HIT: "
                            + question.name()
                            + " (TTL="
                            + remainingTtl
                            + " seconds)"
            );

            return ResolverResponseFactory.create(
                    clientQuery,
                    cached,
                    remainingTtl
            );
        }

        System.out.println(
                "CACHE MISS: "
                        + question.name()
        );

        String currentServer =
                rootServers.get(0);

        int rootServerIndex = 0;

        boolean queryingRootServer = true;

        int maxDepth = 20;

        while (maxDepth-- > 0) {

            System.out.println(
                    "Querying Server: "
                            + currentServer
            );

            DnsMessage upstreamQuery =
                    ResolverQueryFactory.create(question);

            DnsMessage upstreamResponse;

            try {
                upstreamResponse =
                        client.query(
                                currentServer,
                                upstreamQuery
                        );
            } catch (UpstreamDnsException e) {

                if (queryingRootServer
                        && rootServerIndex
                        < rootServers.size() - 1) {

                    currentServer =
                            rootServers.get(
                                    ++rootServerIndex
                            );

                    System.out.println(
                            "Root server failed; retrying with "
                                    + currentServer
                    );

                    continue;
                }

                throw e;
            }

            System.out.println("--------------------------------");

            System.out.println(
                    "Answers     : "
                            + upstreamResponse.answers().size()
            );

            System.out.println(
                    "Authorities : "
                            + upstreamResponse.authorities().size()
            );

            System.out.println(
                    "Additionals : "
                            + upstreamResponse.additionals().size()
            );

            for (DnsRecord record :
                    upstreamResponse.authorities()) {

                System.out.println(
                        "AUTH -> type="
                                + record.type()
                                + " name="
                                + record.name()
                );
            }

            for (DnsRecord record :
                    upstreamResponse.additionals()) {

                System.out.println(
                        "ADD -> type="
                                + record.type()
                                + " name="
                                + record.name()
                );
            }

            System.out.println("--------------------------------");

            int rcode =
                    upstreamResponse.header().flags()
                            & 0x000F;

            if (rcode == 3) {

                System.out.println(
                        "NXDOMAIN received for "
                                + question.name()
                );

                DnsRecord soa =
                        findSoaRecord(upstreamResponse);

                if (soa != null) {

                    long negativeTtl =
                            SoaRecordUtil.negativeTtl(soa);

                    if (negativeTtl > 0) {

                        long now =
                                System.currentTimeMillis();

                        long expiresAt =
                                now
                                        + (negativeTtl * 1000);

                        NegativeCacheEntry entry =
                                new NegativeCacheEntry(
                                        upstreamResponse,
                                        now,
                                        expiresAt
                                );

                        negativeCache.put(
                                question,
                                NegativeCacheType.NXDOMAIN,
                                entry
                        );

                        System.out.println(
                                "Stored NXDOMAIN in negative cache "
                                        + "(TTL="
                                        + negativeTtl
                                        + " seconds)"
                        );
                    }
                }

                return ResolverResponseFactory.fromUpstream(
                        clientQuery,
                        upstreamResponse
                );
            }

            if (rcode == 0
                    && upstreamResponse.answers().isEmpty()) {

                DnsRecord soa =
                        findSoaRecord(upstreamResponse);

                if (soa != null) {

                    long negativeTtl =
                            SoaRecordUtil.negativeTtl(soa);

                    if (negativeTtl > 0) {

                        long now =
                                System.currentTimeMillis();

                        long expiresAt =
                                now
                                        + (negativeTtl * 1000);

                        NegativeCacheEntry entry =
                                new NegativeCacheEntry(
                                        upstreamResponse,
                                        now,
                                        expiresAt
                                );

                        negativeCache.put(
                                question,
                                NegativeCacheType.NODATA,
                                entry
                        );

                        System.out.println(
                                "Stored NODATA in negative cache "
                                        + "(TTL="
                                        + negativeTtl
                                        + " seconds)"
                        );
                    }

                    return ResolverResponseFactory.fromUpstream(
                            clientQuery,
                            upstreamResponse
                    );
                }
            }

            if (!upstreamResponse.answers().isEmpty()) {

                long ttl =
                        upstreamResponse
                                .answers()
                                .get(0)
                                .ttl();

                cache.put(
                        question,
                        upstreamResponse,
                        ttl
                );

                System.out.println(
                        "Stored in cache (TTL="
                                + ttl
                                + " seconds)"
                );

                CachedDnsData cachedResponse =
                        cache.get(question);

                long remainingTtl =
                        cache.remainingTtl(question);

                return ResolverResponseFactory.create(
                        clientQuery,
                        cachedResponse,
                        remainingTtl
                );
            }

            if (upstreamResponse.authorities().isEmpty()) {

                throw new RuntimeException(
                        "No authority records found."
                );
            }

            String nextServer =
                    findGlueRecord(upstreamResponse);

            if (nextServer == null) {

                throw new RuntimeException(
                        "No glue record found."
                );
            }

            System.out.println(
                    "Following delegation -> "
                            + nextServer
            );

            currentServer =
                    nextServer;

            queryingRootServer = false;
        }

        throw new RuntimeException(
                "Maximum recursion depth exceeded."
        );
    }

    private DnsRecord findSoaRecord(
            DnsMessage response
    ) {

        for (DnsRecord record :
                response.authorities()) {

            if (record.type() == 6) {
                return record;
            }
        }

        return null;
    }

    private String findGlueRecord(
            DnsMessage response
    ) {

        for (DnsRecord record :
                response.additionals()) {

            if (record.type() == 1) {

                String ip =
                        DnsRecordUtil.getIpv4Address(record);

                if (ip != null) {
                    return ip;
                }
            }
        }

        return null;
    }
}
