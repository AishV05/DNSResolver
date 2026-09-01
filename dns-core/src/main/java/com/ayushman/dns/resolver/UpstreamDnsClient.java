package com.ayushman.dns.resolver;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;

import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsPacketParser;
import com.ayushman.dns.protocol.DnsPacketWriter;

public class UpstreamDnsClient {

    private static final int DNS_PORT = 53;

    private static final int DEFAULT_TIMEOUT_MILLIS = 2_000;

    private static final int DEFAULT_MAX_ATTEMPTS = 2;

    private static final int MAX_UDP_PACKET_SIZE = 65_535;

    private final int timeoutMillis;

    private final int maxAttempts;

    private final int port;

    public UpstreamDnsClient() {
        this(
                DEFAULT_TIMEOUT_MILLIS,
                DEFAULT_MAX_ATTEMPTS,
                DNS_PORT
        );
    }

    public UpstreamDnsClient(
            int timeoutMillis,
            int maxAttempts,
            int port
    ) {

        if (timeoutMillis <= 0) {
            throw new IllegalArgumentException(
                    "timeoutMillis must be positive"
            );
        }

        if (maxAttempts <= 0) {
            throw new IllegalArgumentException(
                    "maxAttempts must be positive"
            );
        }

        if (port < 1 || port > 65_535) {
            throw new IllegalArgumentException(
                    "port must be between 1 and 65535"
            );
        }

        this.timeoutMillis = timeoutMillis;
        this.maxAttempts = maxAttempts;
        this.port = port;
    }

    public DnsMessage query(
            String serverIp,
            DnsMessage query
    ) throws Exception {

        byte[] request = DnsPacketWriter.buildQuery(query);

        InetAddress serverAddress =
                InetAddress.getByName(serverIp);

        IOException lastFailure = null;

        for (int attempt = 1;
                attempt <= maxAttempts;
                attempt++) {

            try {

                DnsMessage response =
                        queryOverUdp(
                                serverAddress,
                                request,
                                query.header().id()
                        );

                if (isTruncated(response)) {

                    return queryOverTcp(
                            serverAddress,
                            request,
                            query.header().id()
                    );
                }

                return response;

            } catch (IOException e) {
                lastFailure = e;
            }
        }

        throw new UpstreamDnsException(
                "No valid DNS response from "
                        + serverIp
                        + " after "
                        + maxAttempts
                        + " attempt(s)",
                lastFailure
        );
    }

    private DnsMessage queryOverUdp(
            InetAddress serverAddress,
            byte[] request,
            int expectedTransactionId
    ) throws IOException {

        try (DatagramSocket socket = new DatagramSocket()) {

            socket.connect(
                    new InetSocketAddress(
                            serverAddress,
                            port
                    )
            );

            socket.setSoTimeout(timeoutMillis);

            DatagramPacket packet = new DatagramPacket(
                    request,
                    request.length
            );

            socket.send(packet);

            long deadline =
                    System.nanoTime()
                            + (timeoutMillis * 1_000_000L);

            while (true) {

                int remainingMillis =
                        remainingTimeoutMillis(deadline);

                socket.setSoTimeout(remainingMillis);

                byte[] buffer =
                        new byte[MAX_UDP_PACKET_SIZE];

                DatagramPacket responsePacket =
                        new DatagramPacket(
                                buffer,
                                buffer.length
                        );

                socket.receive(responsePacket);

                DnsMessage response =
                        parseResponse(
                                responsePacket.getData(),
                                responsePacket.getLength()
                        );

                if (response.header().id()
                        != expectedTransactionId) {

                    continue;
                }

                ensureResponse(response);

                return response;
            }
        }
    }

    private DnsMessage queryOverTcp(
            InetAddress serverAddress,
            byte[] request,
            int expectedTransactionId
    ) throws IOException {

        if (request.length > 65_535) {
            throw new UpstreamDnsException(
                    "DNS TCP query exceeds 65535 bytes"
            );
        }

        try (Socket socket = new Socket()) {

            socket.connect(
                    new InetSocketAddress(
                            serverAddress,
                            port
                    ),
                    timeoutMillis
            );

            socket.setSoTimeout(timeoutMillis);

            DataOutputStream output =
                    new DataOutputStream(
                            socket.getOutputStream()
                    );

            output.writeShort(request.length);
            output.write(request);
            output.flush();

            DataInputStream input =
                    new DataInputStream(
                            socket.getInputStream()
                    );

            int responseLength =
                    input.readUnsignedShort();

            if (responseLength == 0) {
                throw new UpstreamDnsException(
                        "Upstream DNS TCP response was empty"
                );
            }

            byte[] responseData =
                    new byte[responseLength];

            input.readFully(responseData);

            DnsMessage response =
                    parseResponse(
                            responseData,
                            responseData.length
                    );

            if (response.header().id()
                    != expectedTransactionId) {

                throw new UpstreamDnsException(
                        "Upstream DNS TCP response "
                                + "used an unexpected transaction ID"
                );
            }

            ensureResponse(response);

            return response;
        }
    }

    private int remainingTimeoutMillis(
            long deadline
    ) throws SocketTimeoutException {

        long remainingNanos =
                deadline - System.nanoTime();

        if (remainingNanos <= 0) {
            throw new SocketTimeoutException(
                    "Timed out waiting for upstream DNS response"
            );
        }

        long remainingMillis =
                (remainingNanos + 999_999L) / 1_000_000L;

        return (int) Math.min(
                Integer.MAX_VALUE,
                Math.max(1, remainingMillis)
        );
    }

    private DnsMessage parseResponse(
            byte[] data,
            int length
    ) throws UpstreamDnsException {

        byte[] responseData =
                new byte[length];

        System.arraycopy(
                data,
                0,
                responseData,
                0,
                length
        );

        try {
            return DnsPacketParser.parse(responseData);
        } catch (RuntimeException e) {
            throw new UpstreamDnsException(
                    "Malformed upstream DNS response",
                    e
            );
        }
    }

    private void ensureResponse(
            DnsMessage response
    ) throws UpstreamDnsException {

        boolean responseFlagSet =
                (response.header().flags() & 0x8000) != 0;

        if (!responseFlagSet) {
            throw new UpstreamDnsException(
                    "Upstream DNS packet was not a response"
            );
        }
    }

    private boolean isTruncated(
            DnsMessage response
    ) {

        return (response.header().flags() & 0x0200) != 0;
    }
}
