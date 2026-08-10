package com.ayushman.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.ayushman.dns.protocol.DnsHeader;
import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsPacketParser;
import com.ayushman.dns.protocol.DnsPacketWriter;
import com.ayushman.dns.protocol.DnsQuestion;
import com.ayushman.dns.protocol.DnsRecord;
import com.ayushman.dns.resolver.RecursiveResolver;

public class DnsRequestHandlerTest {

    private static final InetAddress LOOPBACK =
            InetAddress.getLoopbackAddress();

    @Test
    void shouldSendResolverResponseToOriginalClient()
            throws Exception {

        DnsMessage query = createQuery(1234);

        DnsMessage resolverResponse =
                createAnswerResponse(query);

        StubResolver resolver =
                StubResolver.returning(resolverResponse);

        DnsMessage response =
                handleRequest(query, resolver);

        assertEquals(1234, response.header().id());
        assertEquals(1, response.answers().size());
        assertEquals("example.com", response.answers().get(0).name());
        assertEquals(1, resolver.callCount);
    }

    @Test
    void shouldReturnServFailWhenResolverThrows()
            throws Exception {

        DnsMessage query = createQuery(4321);

        StubResolver resolver =
                StubResolver.failing(
                        new RuntimeException("Upstream unavailable")
                );

        DnsMessage response =
                handleRequest(query, resolver);

        assertEquals(4321, response.header().id());
        assertEquals(2, response.header().flags() & 0x000F);
        assertEquals(1, response.questions().size());
        assertEquals("example.com", response.questions().get(0).name());
        assertEquals(1, resolver.callCount);
    }

    @Test
    void shouldReturnFormErrForMalformedPacket()
            throws Exception {

        StubResolver resolver =
                StubResolver.failing(
                        new RuntimeException(
                                "Resolver must not be called"
                        )
                );

        DnsMessage response =
                handleRawRequest(
                        new byte[] {
                                0x12, 0x34
                        },
                        resolver
                );

        assertEquals(0x1234, response.header().id());
        assertEquals(1, response.header().flags() & 0x000F);
        assertEquals(0, response.questions().size());
        assertEquals(0, resolver.callCount);
    }

    private DnsMessage handleRequest(
            DnsMessage query,
            StubResolver resolver
    ) throws Exception {

        return handleRawRequest(
                DnsPacketWriter.buildQuery(query),
                resolver
        );
    }

    private DnsMessage handleRawRequest(
            byte[] requestData,
            StubResolver resolver
    ) throws Exception {

        try (DatagramSocket serverSocket =
                new DatagramSocket(0, LOOPBACK);
                DatagramSocket clientSocket =
                        new DatagramSocket(0, LOOPBACK)) {

            clientSocket.setSoTimeout(1_000);

            DatagramPacket requestPacket =
                    new DatagramPacket(
                            requestData,
                            requestData.length,
                            LOOPBACK,
                            clientSocket.getLocalPort()
                    );

            new DnsRequestHandler(
                    serverSocket,
                    requestPacket,
                    resolver
            ).run();

            byte[] responseBuffer = new byte[4_096];

            DatagramPacket responsePacket =
                    new DatagramPacket(
                            responseBuffer,
                            responseBuffer.length
                    );

            clientSocket.receive(responsePacket);

            byte[] responseData =
                    new byte[responsePacket.getLength()];

            System.arraycopy(
                    responsePacket.getData(),
                    responsePacket.getOffset(),
                    responseData,
                    0,
                    responsePacket.getLength()
            );

            return DnsPacketParser.parse(responseData);
        }
    }

    private DnsMessage createQuery(
            int transactionId
    ) {

        DnsQuestion question =
                new DnsQuestion(
                        "example.com",
                        1,
                        1
                );

        return new DnsMessage(
                new DnsHeader(
                        transactionId,
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
    }

    private DnsMessage createAnswerResponse(
            DnsMessage query
    ) {

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

        return new DnsMessage(
                new DnsHeader(
                        query.header().id(),
                        0x8180,
                        1,
                        1,
                        0,
                        0
                ),
                query.questions(),
                List.of(answer),
                List.of(),
                List.of()
        );
    }

    private static class StubResolver
            extends RecursiveResolver {

        private final DnsMessage response;

        private final Exception failure;

        private int callCount;

        private StubResolver(
                DnsMessage response,
                Exception failure
        ) {

            this.response = response;
            this.failure = failure;
        }

        static StubResolver returning(
                DnsMessage response
        ) {

            return new StubResolver(response, null);
        }

        static StubResolver failing(
                Exception failure
        ) {

            return new StubResolver(null, failure);
        }

        @Override
        public DnsMessage resolve(
                DnsMessage clientQuery
        ) throws Exception {

            callCount++;

            if (failure != null) {
                throw failure;
            }

            return response;
        }
    }
}
