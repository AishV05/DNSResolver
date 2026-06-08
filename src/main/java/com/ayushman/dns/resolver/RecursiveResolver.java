package com.ayushman.dns.resolver;

import java.util.List;

import com.ayushman.dns.protocol.DnsHeader;
import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsQuestion;
import com.ayushman.dns.protocol.DnsRecord;

public class RecursiveResolver {

    private final UpstreamDnsClient client =
            new UpstreamDnsClient();

    public DnsMessage resolve(DnsMessage clientQuery)
            throws Exception {

        String currentServer =
                RootServers.ROOT_SERVERS.get(0);

        int maxDepth = 20;

        while (maxDepth-- > 0) {

            System.out.println(
                    "Querying Server: "
                            + currentServer
            );

            DnsQuestion question =
                    clientQuery.questions().get(0);

            DnsMessage upstreamQuery =
                    ResolverQueryFactory.create(question);

            DnsMessage upstreamResponse =
                    client.query(
                            currentServer,
                            upstreamQuery
                    );

            System.out.println(
                    "------------------------------------------------"
            );

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

            System.out.println(
                    "------------------------------------------------"
            );

            // Final answer found
            if (!upstreamResponse.answers().isEmpty()) {

                System.out.println(
                        "Answer count: "
                                + upstreamResponse.answers().size()
                );

                return adaptForClient(
                        clientQuery,
                        upstreamResponse
                );
            }

            List<DnsRecord> authorities =
                    upstreamResponse.authorities();

            if (authorities.isEmpty()) {

                throw new RuntimeException(
                        "No authority records found"
                );
            }

            String nextServerIp =
                    findGlueRecord(
                            upstreamResponse
                    );

            if (nextServerIp == null) {

                throw new RuntimeException(
                        "No glue record found"
                );
            }

            System.out.println(
                    "Following delegation -> "
                            + nextServerIp
            );

            currentServer = nextServerIp;
        }

        throw new RuntimeException(
                "Maximum recursion depth exceeded"
        );
    }

    private DnsMessage adaptForClient(
            DnsMessage clientQuery,
            DnsMessage upstreamResponse
    ) {

        DnsHeader header =
                new DnsHeader(
                        clientQuery.header().id(),
                        upstreamResponse.header().flags(),
                        upstreamResponse.header().qdCount(),
                        upstreamResponse.header().anCount(),
                        upstreamResponse.header().nsCount(),
                        upstreamResponse.header().arCount()
                );

        return new DnsMessage(
                header,
                upstreamResponse.questions(),
                upstreamResponse.answers(),
                upstreamResponse.authorities(),
                upstreamResponse.additionals()
        );
    }

    private String findGlueRecord(
            DnsMessage response
    ) {

        for (DnsRecord record :
                response.additionals()) {

            if (record.type() == 1) {

                String ip =
                        DnsRecordUtil
                                .getIpv4Address(record);

                if (ip != null) {
                    return ip;
                }
            }
        }

        return null;
    }
}