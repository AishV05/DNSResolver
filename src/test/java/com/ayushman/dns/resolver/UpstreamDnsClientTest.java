package com.ayushman.dns.resolver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;

import com.ayushman.dns.protocol.DnsHeader;
import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsPacketParser;
import com.ayushman.dns.protocol.DnsPacketWriter;
import com.ayushman.dns.protocol.DnsQuestion;
import com.ayushman.dns.protocol.DnsRecord;
import com.ayushman.dns.protocol.EdnsInfo;

public class UpstreamDnsClientTest {

    private static final String LOOPBACK_ADDRESS =
            "127.0.0.1";

    @Test
    void shouldReturnMatchingUdpResponse()
            throws Exception {

        InetAddress loopback =
                InetAddress.getByName(LOOPBACK_ADDRESS);

        try (DatagramSocket server =
                new DatagramSocket(0, loopback)) {

            ExecutorService executor =
                    Executors.newSingleThreadExecutor();

            try {
                Future<?> responseTask =
                        executor.submit(() -> {
                            DatagramPacket requestPacket =
                                    receiveUdp(server);

                            DnsMessage request =
                                    parseUdpPacket(requestPacket);

                            sendUdpResponse(
                                    server,
                                    requestPacket,
                                    createAnswerResponse(request)
                            );
                        });

                UpstreamDnsClient client =
                        new UpstreamDnsClient(
                                500,
                                1,
                                server.getLocalPort()
                        );

                DnsMessage response =
                        client.query(
                                LOOPBACK_ADDRESS,
                                createQuery(1234)
                        );

                responseTask.get(2, TimeUnit.SECONDS);

                assertEquals(1234, response.header().id());
                assertEquals(1, response.answers().size());
                assertEquals(1, response.answers().get(0).type());
            } finally {
                executor.shutdownNow();
            }
        }
    }

    @Test
    void shouldSendEdnsOptInUdpQuery()
            throws Exception {

        InetAddress loopback =
                InetAddress.getByName(LOOPBACK_ADDRESS);

        try (DatagramSocket server =
                new DatagramSocket(0, loopback)) {

            ExecutorService executor =
                    Executors.newSingleThreadExecutor();

            try {
                AtomicReference<DnsMessage> receivedQuery =
                        new AtomicReference<>();

                Future<?> responseTask =
                        executor.submit(() -> {
                            DatagramPacket requestPacket =
                                    receiveUdp(server);

                            DnsMessage request =
                                    parseUdpPacket(requestPacket);

                            receivedQuery.set(request);

                            sendUdpResponse(
                                    server,
                                    requestPacket,
                                    createAnswerResponse(request)
                            );
                        });

                UpstreamDnsClient client =
                        new UpstreamDnsClient(
                                500,
                                1,
                                server.getLocalPort()
                        );

                DnsMessage response =
                        client.query(
                                LOOPBACK_ADDRESS,
                                createQueryWithEdns(3456)
                        );

                responseTask.get(2, TimeUnit.SECONDS);

                EdnsInfo edns =
                        receivedQuery.get()
                                .edns()
                                .orElseThrow();

                assertEquals(3456, response.header().id());
                assertEquals(1_232, edns.udpPayloadSize());
                assertEquals(0, edns.version());
                assertEquals(0, edns.flags());
            } finally {
                executor.shutdownNow();
            }
        }
    }

    @Test
    void shouldIgnoreUdpResponseWithUnexpectedTransactionId()
            throws Exception {

        InetAddress loopback =
                InetAddress.getByName(LOOPBACK_ADDRESS);

        try (DatagramSocket server =
                new DatagramSocket(0, loopback)) {

            ExecutorService executor =
                    Executors.newSingleThreadExecutor();

            try {
                Future<?> responseTask =
                        executor.submit(() -> {
                            DatagramPacket requestPacket =
                                    receiveUdp(server);

                            DnsMessage request =
                                    parseUdpPacket(requestPacket);

                            sendUdpResponse(
                                    server,
                                    requestPacket,
                                    createAnswerResponse(
                                            request,
                                            request.header().id() + 1
                                    )
                            );

                            sendUdpResponse(
                                    server,
                                    requestPacket,
                                    createAnswerResponse(request)
                            );
                        });

                UpstreamDnsClient client =
                        new UpstreamDnsClient(
                                500,
                                1,
                                server.getLocalPort()
                        );

                DnsMessage response =
                        client.query(
                                LOOPBACK_ADDRESS,
                                createQuery(4321)
                        );

                responseTask.get(2, TimeUnit.SECONDS);

                assertEquals(4321, response.header().id());
            } finally {
                executor.shutdownNow();
            }
        }
    }

    @Test
    void shouldRetryUdpAfterTimeout()
            throws Exception {

        InetAddress loopback =
                InetAddress.getByName(LOOPBACK_ADDRESS);

        try (DatagramSocket server =
                new DatagramSocket(0, loopback)) {

            ExecutorService executor =
                    Executors.newSingleThreadExecutor();

            try {
                Future<Integer> responseTask =
                        executor.submit(() -> {
                            receiveUdp(server);

                            DatagramPacket retryPacket =
                                    receiveUdp(server);

                            DnsMessage retryRequest =
                                    parseUdpPacket(retryPacket);

                            sendUdpResponse(
                                    server,
                                    retryPacket,
                                    createAnswerResponse(retryRequest)
                            );

                            return 2;
                        });

                UpstreamDnsClient client =
                        new UpstreamDnsClient(
                                100,
                                2,
                                server.getLocalPort()
                        );

                DnsMessage response =
                        client.query(
                                LOOPBACK_ADDRESS,
                                createQuery(6789)
                        );

                assertEquals(6789, response.header().id());
                assertEquals(
                        2,
                        responseTask.get(2, TimeUnit.SECONDS)
                );
            } finally {
                executor.shutdownNow();
            }
        }
    }

    @Test
    void shouldFallbackToTcpWhenUdpResponseIsTruncated()
            throws Exception {

        InetAddress loopback =
                InetAddress.getByName(LOOPBACK_ADDRESS);

        try (DatagramSocket udpServer =
                new DatagramSocket(0, loopback);
                ServerSocket tcpServer =
                        new ServerSocket(
                                udpServer.getLocalPort(),
                                10,
                                loopback
                        )) {

            ExecutorService executor =
                    Executors.newFixedThreadPool(2);

            try {
                Future<?> udpTask =
                        executor.submit(() -> {
                            DatagramPacket requestPacket =
                                    receiveUdp(udpServer);

                            DnsMessage request =
                                    parseUdpPacket(requestPacket);

                            sendUdpResponse(
                                    udpServer,
                                    requestPacket,
                                    createTruncatedResponse(request)
                            );
                        });

                Future<?> tcpTask =
                        executor.submit(() -> {
                            try {
                                try (Socket connection =
                                        tcpServer.accept()) {

                                    DataInputStream input =
                                            new DataInputStream(
                                                    connection.getInputStream()
                                            );

                                    int requestLength =
                                            input.readUnsignedShort();

                                    byte[] requestData =
                                            new byte[requestLength];

                                    input.readFully(requestData);

                                    DnsMessage request =
                                            DnsPacketParser.parse(requestData);

                                    byte[] responseData =
                                            DnsPacketWriter.buildResponse(
                                                    createAnswerResponse(request)
                                            );

                                    DataOutputStream output =
                                            new DataOutputStream(
                                                    connection.getOutputStream()
                                            );

                                    output.writeShort(responseData.length);
                                    output.write(responseData);
                                    output.flush();
                                }
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                        });

                UpstreamDnsClient client =
                        new UpstreamDnsClient(
                                500,
                                1,
                                udpServer.getLocalPort()
                        );

                DnsMessage response =
                        client.query(
                                LOOPBACK_ADDRESS,
                                createQuery(2468)
                        );

                udpTask.get(2, TimeUnit.SECONDS);
                tcpTask.get(2, TimeUnit.SECONDS);

                assertEquals(2468, response.header().id());
                assertEquals(1, response.answers().size());
                assertEquals(127, response.answers().get(0).rdata()[0]);
            } finally {
                executor.shutdownNow();
            }
        }
    }

    @Test
    void shouldFailAfterConfiguredUdpTimeouts()
            throws Exception {

        InetAddress loopback =
                InetAddress.getByName(LOOPBACK_ADDRESS);

        try (DatagramSocket server =
                new DatagramSocket(0, loopback)) {

            UpstreamDnsClient client =
                    new UpstreamDnsClient(
                            50,
                            2,
                            server.getLocalPort()
                    );

            UpstreamDnsException exception =
                    assertThrows(
                            UpstreamDnsException.class,
                            () -> client.query(
                                    LOOPBACK_ADDRESS,
                                    createQuery(1357)
                            )
                    );

            assertTrue(
                    exception.getMessage()
                            .contains("after 2 attempt(s)")
            );
        }
    }

    @Test
    void shouldReportMalformedUdpResponse()
            throws Exception {

        InetAddress loopback =
                InetAddress.getByName(LOOPBACK_ADDRESS);

        try (DatagramSocket server =
                new DatagramSocket(0, loopback)) {

            ExecutorService executor =
                    Executors.newSingleThreadExecutor();

            try {
                Future<?> responseTask =
                        executor.submit(() -> {
                            DatagramPacket requestPacket =
                                    receiveUdp(server);

                            byte[] malformed =
                                    new byte[] { 0, 1 };

                            DatagramPacket responsePacket =
                                    new DatagramPacket(
                                            malformed,
                                            malformed.length,
                                            requestPacket.getAddress(),
                                            requestPacket.getPort()
                                    );

                            try {
                                server.send(responsePacket);
                            } catch (Exception e) {
                                throw new RuntimeException(e);
                            }
                        });

                UpstreamDnsClient client =
                        new UpstreamDnsClient(
                                500,
                                1,
                                server.getLocalPort()
                        );

                UpstreamDnsException exception =
                        assertThrows(
                                UpstreamDnsException.class,
                                () -> client.query(
                                        LOOPBACK_ADDRESS,
                                        createQuery(9753)
                                )
                        );

                responseTask.get(2, TimeUnit.SECONDS);

                assertTrue(
                        exception.getCause().getMessage()
                                .contains("Malformed upstream DNS response")
                );
            } finally {
                executor.shutdownNow();
            }
        }
    }

    private static DatagramPacket receiveUdp(
            DatagramSocket server
    ) {

        try {
            byte[] buffer = new byte[4_096];
            DatagramPacket packet =
                    new DatagramPacket(buffer, buffer.length);

            server.receive(packet);

            return packet;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static DnsMessage parseUdpPacket(
            DatagramPacket packet
    ) {

        byte[] data =
                new byte[packet.getLength()];

        System.arraycopy(
                packet.getData(),
                packet.getOffset(),
                data,
                0,
                packet.getLength()
        );

        return DnsPacketParser.parse(data);
    }

    private static void sendUdpResponse(
            DatagramSocket server,
            DatagramPacket requestPacket,
            DnsMessage response
    ) {

        try {
            byte[] responseData =
                    DnsPacketWriter.buildResponse(response);

            DatagramPacket responsePacket =
                    new DatagramPacket(
                            responseData,
                            responseData.length,
                            requestPacket.getAddress(),
                            requestPacket.getPort()
                    );

            server.send(responsePacket);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static DnsMessage createQuery(
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

    private static DnsMessage createQueryWithEdns(
            int transactionId
    ) {

        DnsMessage query = createQuery(transactionId);

        return new DnsMessage(
                query.header(),
                query.questions(),
                query.answers(),
                query.authorities(),
                query.additionals(),
                new EdnsInfo(
                        1_232,
                        0,
                        0,
                        0,
                        new byte[0]
                )
        );
    }

    private static DnsMessage createAnswerResponse(
            DnsMessage request
    ) {

        return createAnswerResponse(
                request,
                request.header().id()
        );
    }

    private static DnsMessage createAnswerResponse(
            DnsMessage request,
            int transactionId
    ) {

        DnsRecord answer =
                new DnsRecord(
                        "example.com",
                        1,
                        1,
                        300,
                        new byte[] {
                                127, 0, 0, 1
                        }
                );

        return new DnsMessage(
                new DnsHeader(
                        transactionId,
                        0x8180,
                        1,
                        1,
                        0,
                        0
                ),
                request.questions(),
                List.of(answer),
                List.of(),
                List.of()
        );
    }

    private static DnsMessage createTruncatedResponse(
            DnsMessage request
    ) {

        return new DnsMessage(
                new DnsHeader(
                        request.header().id(),
                        0x8200,
                        1,
                        0,
                        0,
                        0
                ),
                request.questions(),
                List.of(),
                List.of(),
                List.of()
        );
    }
}
