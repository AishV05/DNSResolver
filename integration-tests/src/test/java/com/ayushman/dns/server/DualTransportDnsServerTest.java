package com.ayushman.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.IntStream;

import org.junit.jupiter.api.Test;

import com.ayushman.dns.policy.DnsPolicyAction;
import com.ayushman.dns.policy.DnsPolicyMatchType;
import com.ayushman.dns.policy.DnsPolicyRule;
import com.ayushman.dns.policy.DnsPolicySnapshot;
import com.ayushman.dns.protocol.DnsHeader;
import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsPacketParser;
import com.ayushman.dns.protocol.DnsPacketWriter;
import com.ayushman.dns.protocol.DnsQuestion;
import com.ayushman.dns.protocol.DnsRecord;
import com.ayushman.dns.resolver.DnsResolver;

class DualTransportDnsServerTest {

    private static final InetAddress LOOPBACK =
            InetAddress.getLoopbackAddress();

    @Test
    void enforcesOneLiveSnapshotOverUdpAndTcpBeforeResolution()
            throws Exception {
        int port = availableDualTransportPort();
        DynamicResolver resolver = new DynamicResolver(false);
        PolicySnapshotStore store = new PolicySnapshotStore(
                PolicySyncMode.REQUIRED
        );
        store.activate(new DnsPolicySnapshot(
                1,
                Instant.parse("2026-10-05T00:00:01Z"),
                List.of(new DnsPolicyRule(
                        "example.com",
                        DnsPolicyMatchType.EXACT,
                        DnsPolicyAction.BLOCK
                ))
        ));
        DnsServer server = new DnsServer(
                ServerConfig.defaults().withPort(port),
                resolver,
                store
        );
        ExecutorService executor = Executors.newSingleThreadExecutor();

        try {
            Future<?> task = start(server, executor);
            waitUntil(server::isRunning, 2_000);

            byte[] query = DnsPacketWriter.buildQuery(createQuery(0x17D0));
            assertEquals(
                    5,
                    DnsPacketParser.parse(exchangeUdp(port, query))
                            .header()
                            .flags()
                            & 0x000F
            );
            assertEquals(
                    5,
                    DnsPacketParser.parse(exchangeTcp(port, query))
                            .header()
                            .flags()
                            & 0x000F
            );
            assertEquals(0, resolver.callCount.get());

            store.activate(new DnsPolicySnapshot(
                    2,
                    Instant.parse("2026-10-05T00:00:02Z"),
                    List.of()
            ));
            assertEquals(
                    0,
                    DnsPacketParser.parse(exchangeTcp(port, query))
                            .header()
                            .flags()
                            & 0x000F
            );
            assertEquals(1, resolver.callCount.get());

            server.close();
            task.get(3, TimeUnit.SECONDS);
        } finally {
            server.close();
            executor.shutdownNow();
        }
    }

    @Test
    void remainsUnreadyAndServesNoRecursiveAnswersUntilPolicyLoads()
            throws Exception {
        int port = availableDualTransportPort();
        DynamicResolver resolver = new DynamicResolver(false);
        PolicySnapshotStore store = new PolicySnapshotStore(
                PolicySyncMode.REQUIRED
        );
        DnsServer server = new DnsServer(
                ServerConfig.defaults().withPort(port),
                resolver,
                store
        );
        ExecutorService executor = Executors.newSingleThreadExecutor();

        try {
            Future<?> task = start(server, executor);
            waitUntil(
                    () -> server.isUdpRunning() && server.isTcpRunning(),
                    2_000
            );

            assertFalse(server.isRunning());
            byte[] query = DnsPacketWriter.buildQuery(createQuery(0x172C));
            assertEquals(
                    2,
                    DnsPacketParser.parse(exchangeUdp(port, query))
                            .header()
                            .flags()
                            & 0x000F
            );
            assertEquals(
                    2,
                    DnsPacketParser.parse(exchangeTcp(port, query))
                            .header()
                            .flags()
                            & 0x000F
            );
            assertEquals(0, resolver.callCount.get());

            store.activate(new DnsPolicySnapshot(
                    0,
                    Instant.parse("2026-10-04T00:00:00Z"),
                    List.of()
            ));
            waitUntil(server::isRunning, 2_000);

            assertEquals(
                    0,
                    DnsPacketParser.parse(exchangeUdp(port, query))
                            .header()
                            .flags()
                            & 0x000F
            );
            assertEquals(1, resolver.callCount.get());

            server.close();
            task.get(3, TimeUnit.SECONDS);
        } finally {
            server.close();
            executor.shutdownNow();
        }
    }

    @Test
    void truncatesUdpAndReturnsTheCompleteTcpRetry()
            throws Exception {
        int port = availableDualTransportPort();
        DynamicResolver resolver = new DynamicResolver(true);
        DnsServer server = new DnsServer(
                ServerConfig.defaults().withPort(port),
                resolver
        );
        ExecutorService executor = Executors.newSingleThreadExecutor();

        try {
            Future<?> task = start(server, executor);
            waitUntil(server::isRunning, 2_000);

            byte[] query = DnsPacketWriter.buildQuery(createQuery(0x1234));
            byte[] udpBytes = exchangeUdp(port, query);
            DnsMessage udpResponse = DnsPacketParser.parse(udpBytes);

            assertTrue((udpResponse.header().flags() & 0x0200) != 0);
            assertEquals(0, udpResponse.answers().size());
            assertTrue(udpBytes.length <= 512);

            DnsMessage tcpResponse;
            try (Socket socket = new Socket(LOOPBACK, port)) {
                socket.setSoTimeout(2_000);
                DataOutputStream output = new DataOutputStream(
                        socket.getOutputStream()
                );
                DataInputStream input = new DataInputStream(
                        socket.getInputStream()
                );
                writeFrame(output, query);
                tcpResponse = DnsPacketParser.parse(readFrame(input));
            }

            assertEquals(10, tcpResponse.answers().size());
            assertEquals(0, tcpResponse.header().flags() & 0x0200);
            assertEquals(2, resolver.callCount.get());
            assertEquals(
                    1,
                    server.metrics().snapshot().udpReceivedRequests()
            );
            assertEquals(
                    1,
                    server.metrics().snapshot().tcpReceivedRequests()
            );

            server.close();
            task.get(3, TimeUnit.SECONDS);
            assertFalse(server.isRunning());
        } finally {
            server.close();
            executor.shutdownNow();
        }
    }

    @Test
    void supportsFragmentedAndPipelinedFramesWithConnectionReuse()
            throws Exception {
        int port = availableDualTransportPort();
        DynamicResolver resolver = new DynamicResolver(false);
        DnsServer server = new DnsServer(
                ServerConfig.defaults().withPort(port),
                resolver
        );
        ExecutorService executor = Executors.newSingleThreadExecutor();

        try {
            Future<?> task = start(server, executor);
            waitUntil(server::isRunning, 2_000);

            try (Socket socket = new Socket(LOOPBACK, port)) {
                socket.setSoTimeout(2_000);
                DataOutputStream output = new DataOutputStream(
                        socket.getOutputStream()
                );
                DataInputStream input = new DataInputStream(
                        socket.getInputStream()
                );

                byte[] first = DnsPacketWriter.buildQuery(createQuery(101));
                output.write((first.length >>> 8) & 0xFF);
                output.flush();
                output.write(first.length & 0xFF);
                output.write(first, 0, first.length / 2);
                output.flush();
                output.write(first, first.length / 2,
                        first.length - first.length / 2);
                output.flush();

                byte[] second = DnsPacketWriter.buildQuery(createQuery(202));
                writeFrame(output, second);

                assertEquals(
                        101,
                        DnsPacketParser.parse(readFrame(input)).header().id()
                );
                assertEquals(
                        202,
                        DnsPacketParser.parse(readFrame(input)).header().id()
                );
            }

            assertEquals(2, resolver.callCount.get());
            server.close();
            task.get(3, TimeUnit.SECONDS);
        } finally {
            server.close();
            executor.shutdownNow();
        }
    }

    @Test
    void boundsPerClientConnectionsAndIdleTime()
            throws Exception {
        int port = availableDualTransportPort();
        Properties properties = new Properties();
        properties.setProperty("dns.tcp.maxConnections", "1");
        properties.setProperty("dns.tcp.maxConnectionsPerClient", "1");
        properties.setProperty("dns.tcp.idleTimeoutMillis", "150");
        ServerConfig config = ServerConfig.from(
                properties,
                Map.of()
        ).withPort(port);
        ServerMetrics metrics = new ServerMetrics();
        DnsRequestProcessor processor = new DnsRequestProcessor(
                new DynamicResolver(false),
                metrics
        );
        TcpDnsServer server = new TcpDnsServer(
                config,
                processor,
                new RequestAdmissionController(
                        config.tcpMaxRequestBytes(),
                        new ClientRateLimiter(100, 100)
                ),
                metrics
        );
        ExecutorService executor = Executors.newSingleThreadExecutor();

        try {
            Future<?> task = start(server, executor);
            waitUntil(server::isRunning, 2_000);

            try (Socket first = new Socket(LOOPBACK, port)) {
                first.setSoTimeout(2_000);
                waitUntil(
                        () -> metrics.snapshot().tcpConnectionsActive() == 1,
                        2_000
                );
                try (Socket rejected = new Socket(LOOPBACK, port)) {
                    rejected.setSoTimeout(2_000);
                    waitUntil(
                            () -> metrics.snapshot()
                                    .tcpConnectionLimitRejections() == 1,
                            2_000
                    );
                    assertEquals(-1, rejected.getInputStream().read());
                }
                waitUntil(
                        () -> metrics.snapshot().tcpConnectionTimeouts() == 1,
                        2_000
                );
                assertEquals(-1, first.getInputStream().read());
            }

            assertEquals(
                    1,
                    metrics.snapshot().tcpConnectionLimitRejections()
            );
            assertEquals(1, metrics.snapshot().tcpConnectionTimeouts());
            server.close();
            task.get(3, TimeUnit.SECONDS);
        } finally {
            server.close();
            executor.shutdownNow();
        }
    }

    @Test
    void gracefulShutdownClosesActiveTcpConnections()
            throws Exception {
        int port = availableDualTransportPort();
        DnsServer server = new DnsServer(
                ServerConfig.defaults().withPort(port),
                new DynamicResolver(false)
        );
        ExecutorService executor = Executors.newSingleThreadExecutor();

        try {
            Future<?> task = start(server, executor);
            waitUntil(server::isRunning, 2_000);

            try (Socket connection = new Socket(LOOPBACK, port)) {
                connection.setSoTimeout(2_000);
                waitUntil(
                        () -> server.metrics().snapshot()
                                .tcpConnectionsActive() == 1,
                        2_000
                );

                server.close();

                assertEquals(-1, connection.getInputStream().read());
                task.get(3, TimeUnit.SECONDS);
                waitUntil(
                        () -> server.metrics().snapshot()
                                .tcpConnectionsActive() == 0,
                        2_000
                );
            }
            assertFalse(server.isRunning());
        } finally {
            server.close();
            executor.shutdownNow();
        }
    }

    @Test
    void rejectsZeroLengthAndSlowPartialFrames()
            throws Exception {
        int port = availableDualTransportPort();
        Properties properties = new Properties();
        properties.setProperty("dns.tcp.idleTimeoutMillis", "1000");
        properties.setProperty("dns.tcp.messageTimeoutMillis", "100");
        ServerConfig config = ServerConfig.from(
                properties,
                Map.of()
        ).withPort(port);
        ServerMetrics metrics = new ServerMetrics();
        TcpDnsServer server = new TcpDnsServer(
                config,
                new DnsRequestProcessor(
                        new DynamicResolver(false),
                        metrics
                ),
                new RequestAdmissionController(
                        config.tcpMaxRequestBytes(),
                        new ClientRateLimiter(100, 100)
                ),
                metrics
        );
        ExecutorService executor = Executors.newSingleThreadExecutor();

        try {
            Future<?> task = start(server, executor);
            waitUntil(server::isRunning, 2_000);

            try (Socket zero = new Socket(LOOPBACK, port)) {
                zero.setSoTimeout(2_000);
                zero.getOutputStream().write(new byte[] {0, 0});
                zero.getOutputStream().flush();
                assertEquals(-1, zero.getInputStream().read());
            }

            try (Socket slow = new Socket(LOOPBACK, port)) {
                slow.setSoTimeout(2_000);
                slow.getOutputStream().write(0);
                slow.getOutputStream().flush();
                Thread.sleep(200);
                assertEquals(-1, slow.getInputStream().read());
            }

            waitUntil(
                    () -> metrics.snapshot().tcpProtocolErrors() >= 1
                            && metrics.snapshot().tcpConnectionTimeouts() >= 1,
                    2_000
            );
            server.close();
            task.get(3, TimeUnit.SECONDS);
        } finally {
            server.close();
            executor.shutdownNow();
        }
    }

    @Test
    void failsClosedWhenOnlyOneTransportCanBind()
            throws Exception {
        try (ServerSocket occupied = new ServerSocket(0)) {
            int port = occupied.getLocalPort();
            try (DatagramSocket udpProbe = new DatagramSocket(port)) {
                // Prove UDP is available independently before the server starts.
            }

            DnsServer server = new DnsServer(
                    ServerConfig.defaults().withPort(port),
                    new DynamicResolver(false)
            );
            ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                Future<?> task = start(server, executor);
                assertThrows(
                        ExecutionException.class,
                        () -> task.get(3, TimeUnit.SECONDS)
                );
                waitUntil(
                        () -> !server.isUdpRunning()
                                && !server.isTcpRunning(),
                        2_000
                );
                assertFalse(server.isRunning());
            } finally {
                server.close();
                executor.shutdownNow();
            }
        }
    }

    private Future<?> start(
            DnsServer server,
            ExecutorService executor
    ) {
        return executor.submit(() -> {
            try {
                server.start();
            } catch (Exception failure) {
                throw new RuntimeException(failure);
            }
        });
    }

    private Future<?> start(
            TcpDnsServer server,
            ExecutorService executor
    ) {
        return executor.submit(() -> {
            try {
                server.start();
            } catch (Exception failure) {
                throw new RuntimeException(failure);
            }
        });
    }

    private void waitUntil(
            CheckedCondition condition,
            long timeoutMillis
    ) throws Exception {
        long deadline = System.nanoTime()
                + TimeUnit.MILLISECONDS.toNanos(timeoutMillis);
        while (!condition.evaluate() && System.nanoTime() < deadline) {
            Thread.sleep(10);
        }
        assertTrue(condition.evaluate(), "condition was not met in time");
    }

    private int availableDualTransportPort()
            throws Exception {
        for (int attempt = 0; attempt < 20; attempt++) {
            try (ServerSocket tcp = new ServerSocket(0, 1, LOOPBACK);
                    DatagramSocket udp = new DatagramSocket(
                            tcp.getLocalPort(),
                            LOOPBACK
                    )) {
                return tcp.getLocalPort();
            }
        }
        throw new IllegalStateException("could not reserve a dual port");
    }

    private byte[] exchangeUdp(
            int port,
            byte[] request
    ) throws Exception {
        try (DatagramSocket socket = new DatagramSocket(0, LOOPBACK)) {
            socket.setSoTimeout(2_000);
            socket.send(new DatagramPacket(
                    request,
                    request.length,
                    LOOPBACK,
                    port
            ));
            DatagramPacket response = new DatagramPacket(
                    new byte[4_096],
                    4_096
            );
            socket.receive(response);
            return java.util.Arrays.copyOfRange(
                    response.getData(),
                    response.getOffset(),
                    response.getOffset() + response.getLength()
            );
        }
    }

    private byte[] exchangeTcp(
            int port,
            byte[] request
    ) throws Exception {
        try (Socket socket = new Socket(LOOPBACK, port)) {
            socket.setSoTimeout(2_000);
            DataOutputStream output = new DataOutputStream(
                    socket.getOutputStream()
            );
            DataInputStream input = new DataInputStream(
                    socket.getInputStream()
            );
            writeFrame(output, request);
            return readFrame(input);
        }
    }

    private void writeFrame(
            DataOutputStream output,
            byte[] message
    ) throws Exception {
        output.writeShort(message.length);
        output.write(message);
        output.flush();
    }

    private byte[] readFrame(
            DataInputStream input
    ) throws Exception {
        int length = input.readUnsignedShort();
        byte[] message = new byte[length];
        input.readFully(message);
        return message;
    }

    private DnsMessage createQuery(
            int id
    ) {
        return new DnsMessage(
                new DnsHeader(id, 0x0100, 1, 0, 0, 0),
                List.of(new DnsQuestion("example.com", 1, 1)),
                List.of(),
                List.of(),
                List.of()
        );
    }

    @FunctionalInterface
    private interface CheckedCondition {
        boolean evaluate() throws Exception;
    }

    private static final class DynamicResolver implements DnsResolver {

        private final boolean large;
        private final AtomicInteger callCount = new AtomicInteger();

        private DynamicResolver(
                boolean large
        ) {
            this.large = large;
        }

        @Override
        public DnsMessage resolve(
                DnsMessage query
        ) {
            callCount.incrementAndGet();
            List<DnsRecord> answers = large
                    ? IntStream.range(0, 10)
                            .mapToObj(index -> new DnsRecord(
                                    "record" + index + ".example.com",
                                    16,
                                    1,
                                    300,
                                    new byte[80]
                            ))
                            .toList()
                    : List.of(new DnsRecord(
                            "example.com",
                            1,
                            1,
                            300,
                            new byte[] {1, 2, 3, 4}
                    ));
            return new DnsMessage(
                    new DnsHeader(
                            query.header().id(),
                            0x8180,
                            query.questions().size(),
                            answers.size(),
                            0,
                            0
                    ),
                    query.questions(),
                    answers,
                    List.of(),
                    List.of()
            );
        }
    }
}
