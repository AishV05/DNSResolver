package com.ayushman.dns.resolver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.util.ArrayDeque;
import java.util.List;
import java.util.Queue;

import org.junit.jupiter.api.Test;

import com.ayushman.dns.protocol.DnsHeader;
import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsQuestion;
import com.ayushman.dns.protocol.DnsRecord;

public class RecursiveResolverTest {

    @Test
    void shouldReturnAuthoritativeAnswer() throws Exception {

        DnsQuestion question =
                new DnsQuestion(
                        "example.com",
                        1,
                        1
                );

        DnsMessage clientQuery =
                createClientQuery(
                        1234,
                        question
                );

        DnsRecord answer =
                new DnsRecord(
                        "example.com",
                        1,
                        1,
                        300,
                        new byte[] {
                                1, 2, 3, 4
                        }
                );

        DnsMessage authoritativeResponse =
                createResponse(
                        0x8180,
                        question,
                        List.of(answer),
                        List.of(),
                        List.of()
                );

        MockUpstreamDnsClient client =
                new MockUpstreamDnsClient();

        client.addResponse(
                authoritativeResponse
        );

        RecursiveResolver resolver =
                new RecursiveResolver(client);

        DnsMessage response =
                resolver.resolve(clientQuery);

        assertEquals(
                1234,
                response.header().id()
        );

        assertEquals(
                1,
                response.answers().size()
        );

        assertEquals(
                "example.com",
                response.answers().get(0).name()
        );

        assertEquals(
                1,
                response.answers().get(0).type()
        );

        assertEquals(
                1,
                client.callCount
        );
    }

    @Test
    void shouldUsePositiveCacheOnSecondQuery()
            throws Exception {

        DnsQuestion question =
                new DnsQuestion(
                        "example.com",
                        1,
                        1
                );

        DnsMessage firstQuery =
                createClientQuery(
                        1000,
                        question
                );

        DnsMessage secondQuery =
                createClientQuery(
                        2000,
                        question
                );

        DnsRecord answer =
                new DnsRecord(
                        "example.com",
                        1,
                        1,
                        300,
                        new byte[] {
                                8, 8, 8, 8
                        }
                );

        DnsMessage upstreamResponse =
                createResponse(
                        0x8180,
                        question,
                        List.of(answer),
                        List.of(),
                        List.of()
                );

        MockUpstreamDnsClient client =
                new MockUpstreamDnsClient();

        client.addResponse(
                upstreamResponse
        );

        RecursiveResolver resolver =
                new RecursiveResolver(client);

        DnsMessage firstResponse =
                resolver.resolve(firstQuery);

        DnsMessage secondResponse =
                resolver.resolve(secondQuery);

        assertEquals(
                1000,
                firstResponse.header().id()
        );

        assertEquals(
                2000,
                secondResponse.header().id()
        );

        assertEquals(
                1,
                secondResponse.answers().size()
        );

        assertEquals(
                8,
                secondResponse.answers()
                        .get(0)
                        .rdata()[0]
                        & 0xFF
        );

        assertEquals(
                1,
                client.callCount
        );
    }

    @Test
    void shouldKeepDifferentQueryTypesSeparate()
            throws Exception {

        DnsQuestion aQuestion =
                new DnsQuestion(
                        "example.com",
                        1,
                        1
                );

        DnsQuestion mxQuestion =
                new DnsQuestion(
                        "example.com",
                        15,
                        1
                );

        DnsMessage aQuery =
                createClientQuery(
                        1001,
                        aQuestion
                );

        DnsMessage mxQuery =
                createClientQuery(
                        1002,
                        mxQuestion
                );

        DnsRecord aRecord =
                new DnsRecord(
                        "example.com",
                        1,
                        1,
                        300,
                        new byte[] {
                                1, 2, 3, 4
                        }
                );

        DnsRecord mxRecord =
                new DnsRecord(
                        "example.com",
                        15,
                        1,
                        300,
                        new byte[] {
                                0, 10
                        }
                );

        DnsMessage aResponse =
                createResponse(
                        0x8180,
                        aQuestion,
                        List.of(aRecord),
                        List.of(),
                        List.of()
                );

        DnsMessage mxResponse =
                createResponse(
                        0x8180,
                        mxQuestion,
                        List.of(mxRecord),
                        List.of(),
                        List.of()
                );

        MockUpstreamDnsClient client =
                new MockUpstreamDnsClient();

        client.addResponse(aResponse);
        client.addResponse(mxResponse);

        RecursiveResolver resolver =
                new RecursiveResolver(client);

        DnsMessage aResult =
                resolver.resolve(aQuery);

        DnsMessage mxResult =
                resolver.resolve(mxQuery);

        assertEquals(
                1,
                aResult.answers().get(0).type()
        );

        assertEquals(
                15,
                mxResult.answers().get(0).type()
        );

        assertEquals(
                2,
                client.callCount
        );
    }

    @Test
    void shouldFollowDelegationToAuthoritativeServer()
            throws Exception {

        DnsQuestion question =
                new DnsQuestion(
                        "example.com",
                        1,
                        1
                );

        DnsMessage clientQuery =
                createClientQuery(
                        5000,
                        question
                );

        DnsRecord authority =
                new DnsRecord(
                        "example.com",
                        2,
                        1,
                        86400,
                        new byte[] {
                                1
                        }
                );

        DnsRecord glue =
                new DnsRecord(
                        "ns1.example.com",
                        1,
                        1,
                        300,
                        new byte[] {
                                10, 0, 0, 1
                        }
                );

        DnsMessage delegationResponse =
                createResponse(
                        0x8100,
                        question,
                        List.of(),
                        List.of(authority),
                        List.of(glue)
                );

        DnsRecord answer =
                new DnsRecord(
                        "example.com",
                        1,
                        1,
                        300,
                        new byte[] {
                                93, (byte) 184, (byte) 216, 34   
                            }
                );

        DnsMessage finalResponse =
                createResponse(
                        0x8180,
                        question,
                        List.of(answer),
                        List.of(),
                        List.of()
                );

        MockUpstreamDnsClient client =
                new MockUpstreamDnsClient();

        client.addResponse(
                delegationResponse
        );

        client.addResponse(
                finalResponse
        );

        RecursiveResolver resolver =
                new RecursiveResolver(client);

        DnsMessage response =
                resolver.resolve(clientQuery);

        assertNotNull(response);

        assertEquals(
                1,
                response.answers().size()
        );

        assertEquals(
                "example.com",
                response.answers()
                        .get(0)
                        .name()
        );

        assertEquals(
                2,
                client.callCount
        );

        assertEquals(
        RootServers.ROOT_SERVERS.get(0),
        client.requestedServers.get(0)
        );

        assertEquals(
        "10.0.0.1",
        client.requestedServers.get(1)
        );
    }

    private DnsMessage createClientQuery(
            int id,
            DnsQuestion question
    ) {

        DnsHeader header =
                new DnsHeader(
                        id,
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

    private DnsMessage createResponse(
            int flags,
            DnsQuestion question,
            List<DnsRecord> answers,
            List<DnsRecord> authorities,
            List<DnsRecord> additionals
    ) {

        DnsHeader header =
                new DnsHeader(
                        9999,
                        flags,
                        1,
                        answers.size(),
                        authorities.size(),
                        additionals.size()
                );

        return new DnsMessage(
                header,
                List.of(question),
                answers,
                authorities,
                additionals
        );
    }

    private static class MockUpstreamDnsClient
            extends UpstreamDnsClient {

        private final Queue<DnsMessage> responses =
                new ArrayDeque<>();

        private final List<String> requestedServers =
                new java.util.ArrayList<>();

        private int callCount = 0;

        void addResponse(
                DnsMessage response
        ) {

            responses.add(response);
        }

        @Override
        public DnsMessage query(
                String serverIp,
                DnsMessage query
        ) throws Exception {

            callCount++;

            requestedServers.add(
                    serverIp
            );

            DnsMessage response =
                    responses.poll();

            if (response == null) {

                throw new IllegalStateException(
                        "No mock response available"
                );
            }

            return response;
        }
    }
    @Test
void shouldCacheNxDomain() throws Exception {

    DnsQuestion question =
            new DnsQuestion(
                    "does-not-exist.example",
                    1,
                    1
            );

    DnsMessage firstQuery =
            createClientQuery(
                    6000,
                    question
            );

    DnsMessage secondQuery =
            createClientQuery(
                    6001,
                    question
            );

    DnsRecord soa =
            createSoaRecord();

    DnsMessage nxDomainResponse =
            createResponse(
                    0x8183,
                    question,
                    List.of(),
                    List.of(soa),
                    List.of()
            );

    MockUpstreamDnsClient client =
            new MockUpstreamDnsClient();

    client.addResponse(
            nxDomainResponse
    );

    RecursiveResolver resolver =
            new RecursiveResolver(client);

    DnsMessage firstResponse =
            resolver.resolve(firstQuery);

    DnsMessage secondResponse =
            resolver.resolve(secondQuery);

    assertEquals(
            6000,
            firstResponse.header().id()
    );

    assertEquals(
            6001,
            secondResponse.header().id()
    );

    assertEquals(
            3,
            secondResponse.header().flags() & 0x000F
    );

    assertEquals(
            1,
            client.callCount
    );
}

@Test
void shouldReturnNxDomainFromNegativeCache()
        throws Exception {

    DnsQuestion question =
            new DnsQuestion(
                    "does-not-exist.example",
                    1,
                    1
            );

    DnsMessage firstQuery =
            createClientQuery(
                    6100,
                    question
            );

    DnsMessage secondQuery =
            createClientQuery(
                    6200,
                    question
            );

    DnsRecord soa =
            createSoaRecord();

    DnsMessage nxDomainResponse =
            createResponse(
                    0x8183,
                    question,
                    List.of(),
                    List.of(soa),
                    List.of()
            );

    MockUpstreamDnsClient client =
            new MockUpstreamDnsClient();

    client.addResponse(
            nxDomainResponse
    );

    RecursiveResolver resolver =
            new RecursiveResolver(client);

    resolver.resolve(firstQuery);

    DnsMessage cachedResponse =
            resolver.resolve(secondQuery);

    assertEquals(
            6200,
            cachedResponse.header().id()
    );

    assertEquals(
            3,
            cachedResponse.header().flags() & 0x000F
    );

    assertEquals(
            1,
            cachedResponse.questions().size()
    );

    assertEquals(
            "does-not-exist.example",
            cachedResponse.questions()
                    .get(0)
                    .name()
    );

    assertEquals(
            1,
            client.callCount
    );
}

@Test
void shouldCacheNoData() throws Exception {

    DnsQuestion question =
            new DnsQuestion(
                    "google.com",
                    33,
                    1
            );

    DnsMessage firstQuery =
            createClientQuery(
                    6300,
                    question
            );

    DnsMessage secondQuery =
            createClientQuery(
                    6301,
                    question
            );

    DnsRecord soa =
            createSoaRecord();

    DnsMessage noDataResponse =
            createResponse(
                    0x8180,
                    question,
                    List.of(),
                    List.of(soa),
                    List.of()
            );

    MockUpstreamDnsClient client =
            new MockUpstreamDnsClient();

    client.addResponse(
            noDataResponse
    );

    RecursiveResolver resolver =
            new RecursiveResolver(client);

    DnsMessage firstResponse =
            resolver.resolve(firstQuery);

    DnsMessage secondResponse =
            resolver.resolve(secondQuery);

    assertEquals(
            6300,
            firstResponse.header().id()
    );

    assertEquals(
            6301,
            secondResponse.header().id()
    );

    assertEquals(
            0,
            secondResponse.header().flags() & 0x000F
    );

    assertEquals(
            0,
            secondResponse.answers().size()
    );

    assertEquals(
            1,
            secondResponse.authorities().size()
    );

    assertEquals(
            1,
            client.callCount
    );
}

@Test
void shouldKeepNxDomainAndNoDataSeparate()
        throws Exception {

    DnsQuestion nxDomainQuestion =
            new DnsQuestion(
                    "does-not-exist.example",
                    1,
                    1
            );

    DnsQuestion noDataQuestion =
            new DnsQuestion(
                    "google.com",
                    33,
                    1
            );

    DnsMessage nxDomainQuery =
            createClientQuery(
                    6400,
                    nxDomainQuestion
            );

    DnsMessage noDataQuery =
            createClientQuery(
                    6401,
                    noDataQuestion
            );

    DnsRecord soa =
            createSoaRecord();

    DnsMessage nxDomainResponse =
            createResponse(
                    0x8183,
                    nxDomainQuestion,
                    List.of(),
                    List.of(soa),
                    List.of()
            );

    DnsMessage noDataResponse =
            createResponse(
                    0x8180,
                    noDataQuestion,
                    List.of(),
                    List.of(soa),
                    List.of()
            );

    MockUpstreamDnsClient client =
            new MockUpstreamDnsClient();

    client.addResponse(
            nxDomainResponse
    );

    client.addResponse(
            noDataResponse
    );

    RecursiveResolver resolver =
            new RecursiveResolver(client);

    DnsMessage nxDomainResult =
            resolver.resolve(nxDomainQuery);

    DnsMessage noDataResult =
            resolver.resolve(noDataQuery);

    assertEquals(
            3,
            nxDomainResult.header().flags() & 0x000F
    );

    assertEquals(
            0,
            noDataResult.header().flags() & 0x000F
    );

    assertEquals(
            2,
            client.callCount
    );

    DnsMessage nxDomainCached =
            resolver.resolve(
                    createClientQuery(
                            6500,
                            nxDomainQuestion
                    )
            );

    DnsMessage noDataCached =
            resolver.resolve(
                    createClientQuery(
                            6501,
                            noDataQuestion
                    )
            );

    assertEquals(
            3,
            nxDomainCached.header().flags() & 0x000F
    );

    assertEquals(
            0,
            noDataCached.header().flags() & 0x000F
    );

    assertEquals(
            2,
            client.callCount
    );
}

private DnsRecord createSoaRecord() {

    byte[] rdata = new byte[] {
            1, 'a', 0,
            1, 'b', 0,

            0, 0, 0, 1,
            0, 0, 0, 2,
            0, 0, 0, 3,
            0, 0, 0, 4,

            0, 0, 1, 44
    };

    return new DnsRecord(
            "example.com",
            6,
            1,
            900,
            rdata
    );
}
}