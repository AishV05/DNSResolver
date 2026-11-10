package com.ayushman.dns.resolver;

import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;

import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsPacketParser;
import com.ayushman.dns.protocol.DnsPacketWriter;
import com.ayushman.dns.protocol.DnsQuestion;
import com.ayushman.dns.protocol.EdnsInfo;

public class UpstreamDnsClient {

    private static final int DNS_PORT = 53;

    private static final int DEFAULT_TIMEOUT_MILLIS = 2_000;

    private static final int DEFAULT_MAX_ATTEMPTS = 2;

    public static final int MAX_ATTEMPTS = 5;

    private static final int MAX_UDP_PACKET_SIZE = 65_535;

    private static final int MAX_REJECTED_UDP_RESPONSES = 16;

    private static final int RESPONSE_FLAG = 0x8000;

    private static final int TRUNCATED_FLAG = 0x0200;

    private static final int OPCODE_MASK = 0x7800;

    private static final int RESERVED_Z_FLAG = 0x0040;

    private static final int RCODE_MASK = 0x000F;

    private static final int RCODE_NOERROR = 0;

    private static final int RCODE_NXDOMAIN = 3;

    private final int timeoutMillis;

    private final int maxAttempts;

    private final int port;

    private final ResolverObserver observer;

    public UpstreamDnsClient() {
        this(
                DEFAULT_TIMEOUT_MILLIS,
                DEFAULT_MAX_ATTEMPTS,
                DNS_PORT,
                ResolverObserver.NOOP
        );
    }

    public UpstreamDnsClient(
            int timeoutMillis,
            int maxAttempts,
            int port
    ) {
        this(
                timeoutMillis,
                maxAttempts,
                port,
                ResolverObserver.NOOP
        );
    }

    public UpstreamDnsClient(
            int timeoutMillis,
            int maxAttempts,
            int port,
            ResolverObserver observer
    ) {

        if (timeoutMillis <= 0) {
            throw new IllegalArgumentException(
                    "timeoutMillis must be positive"
            );
        }

        if (maxAttempts <= 0
                || maxAttempts > MAX_ATTEMPTS) {
            throw new IllegalArgumentException(
                            "maxAttempts must be between 1 and "
                            + MAX_ATTEMPTS
            );
        }

        if (port < 1 || port > 65_535) {
            throw new IllegalArgumentException(
                    "port must be between 1 and 65535"
            );
        }

        if (observer == null) {
            throw new IllegalArgumentException(
                    "observer must not be null"
            );
        }

        this.timeoutMillis = timeoutMillis;
        this.maxAttempts = maxAttempts;
        this.port = port;
        this.observer = observer;
    }

    public DnsMessage query(
            String serverIp,
            DnsMessage query
    ) throws Exception {

        byte[] request = DnsPacketWriter.buildQuery(query);

        ExpectedResponse expectedResponse =
                ExpectedResponse.fromOutboundRequest(request);

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
                                expectedResponse
                        );

                if (isTruncated(response)) {

                    return queryOverTcp(
                            serverAddress,
                            request,
                            expectedResponse
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
            ExpectedResponse expectedResponse
    ) throws IOException {

        try (DatagramSocket socket = new DatagramSocket()) {

            socket.connect(
                    new InetSocketAddress(
                            serverAddress,
                            port
                    )
            );

            DatagramPacket packet = new DatagramPacket(
                    request,
                    request.length
            );

            long deadline = deadlineAfterTimeout();

            socket.send(packet);

            byte[] buffer = new byte[MAX_UDP_PACKET_SIZE];
            DatagramPacket responsePacket =
                    new DatagramPacket(buffer, buffer.length);
            UpstreamDnsException lastRejectedResponse = null;
            int rejectedResponseCount = 0;

            while (true) {

                int remainingMillis;

                try {
                    remainingMillis =
                            remainingTimeoutMillis(deadline);
                } catch (SocketTimeoutException timeout) {
                    throw preferredUdpFailure(
                            timeout,
                            lastRejectedResponse
                    );
                }

                socket.setSoTimeout(remainingMillis);

                responsePacket.setLength(buffer.length);

                try {
                    socket.receive(responsePacket);
                } catch (SocketTimeoutException timeout) {
                    throw preferredUdpFailure(
                            timeout,
                            lastRejectedResponse
                    );
                }

                try {
                    ensureExpectedSource(
                            responsePacket,
                            serverAddress
                    );

                    DnsMessage response =
                            parseResponse(
                                    responsePacket.getData(),
                                    responsePacket.getLength()
                            );

                    expectedResponse.validate(response);

                    return response;
                } catch (UpstreamDnsException rejectedResponse) {
                    observer.upstreamResponseRejected();
                    lastRejectedResponse = rejectedResponse;
                    rejectedResponseCount++;

                    if (rejectedResponseCount
                            >= MAX_REJECTED_UDP_RESPONSES) {
                        throw new UpstreamDnsException(
                                "Upstream DNS UDP response discard limit of "
                                        + MAX_REJECTED_UDP_RESPONSES
                                        + " was reached",
                                rejectedResponse
                        );
                    }
                }
            }
        }
    }

    private DnsMessage queryOverTcp(
            InetAddress serverAddress,
            byte[] request,
            ExpectedResponse expectedResponse
    ) throws IOException {

        if (request.length > 65_535) {
            throw new UpstreamDnsException(
                    "DNS TCP query exceeds 65535 bytes"
            );
        }

        try (Socket socket = new Socket()) {

            long deadline = deadlineAfterTimeout();

            socket.connect(
                    new InetSocketAddress(
                            serverAddress,
                            port
                    ),
                    remainingTimeoutMillis(deadline)
            );

            DataOutputStream output =
                    new DataOutputStream(
                            socket.getOutputStream()
                    );

            output.writeShort(request.length);
            output.write(request);
            output.flush();

            InputStream input = socket.getInputStream();

            byte[] lengthPrefix = new byte[2];
            readExactly(
                    socket,
                    input,
                    lengthPrefix,
                    deadline,
                    "two-byte length prefix"
            );

            int responseLength =
                    ((lengthPrefix[0] & 0xFF) << 8)
                            | (lengthPrefix[1] & 0xFF);

            if (responseLength == 0) {
                throw new UpstreamDnsException(
                        "Upstream DNS TCP response was empty"
                );
            }

            byte[] responseData =
                    new byte[responseLength];

            readExactly(
                    socket,
                    input,
                    responseData,
                    deadline,
                    "declared response frame"
            );

            DnsMessage response =
                    parseResponse(
                            responseData,
                            responseData.length
                    );

            expectedResponse.validate(response);

            if (isTruncated(response)) {
                throw new UpstreamDnsException(
                        "Upstream DNS TCP response remained truncated"
                );
            }

            return response;
        } catch (UpstreamDnsException rejectedResponse) {
            observer.upstreamResponseRejected();
            throw rejectedResponse;
        }
    }

    private void ensureExpectedSource(
            DatagramPacket packet,
            InetAddress serverAddress
    ) throws UpstreamDnsException {

        if (!serverAddress.equals(packet.getAddress())
                || packet.getPort() != port) {
            throw new UpstreamDnsException(
                    "Upstream DNS UDP response used an unexpected source endpoint"
            );
        }
    }

    private void readExactly(
            Socket socket,
            InputStream input,
            byte[] destination,
            long deadline,
            String field
    ) throws IOException {

        int offset = 0;

        while (offset < destination.length) {
            socket.setSoTimeout(
                    remainingTimeoutMillis(deadline)
            );

            int count = input.read(
                    destination,
                    offset,
                    destination.length - offset
            );

            if (count < 0) {
                throw new EOFException(
                        "Upstream DNS TCP connection ended before the "
                                + field
                );
            }

            offset += count;
        }
    }

    private long deadlineAfterTimeout() {
        return System.nanoTime()
                + (timeoutMillis * 1_000_000L);
    }

    private IOException preferredUdpFailure(
            SocketTimeoutException timeout,
            UpstreamDnsException lastRejectedResponse
    ) {

        if (lastRejectedResponse == null) {
            return timeout;
        }

        lastRejectedResponse.addSuppressed(timeout);
        return lastRejectedResponse;
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

    private boolean isTruncated(
            DnsMessage response
    ) {

        return (response.header().flags() & TRUNCATED_FLAG) != 0;
    }

    private record ExpectedResponse(
            int transactionId,
            int opcode,
            String canonicalQuestionName,
            int questionType,
            int questionClass,
            boolean ednsRequested,
            int ednsVersion
    ) {

        private static ExpectedResponse fromOutboundRequest(
                byte[] request
        ) throws UpstreamDnsException {

            DnsMessage outbound;

            try {
                outbound = DnsPacketParser.parse(request);
            } catch (RuntimeException e) {
                throw new UpstreamDnsException(
                        "Could not validate the encoded upstream DNS query",
                        e
                );
            }

            if ((outbound.header().flags() & RESPONSE_FLAG) != 0) {
                throw new UpstreamDnsException(
                        "Upstream DNS query must not have the response flag set"
                );
            }

            if (outbound.questions().size() != 1) {
                throw new UpstreamDnsException(
                        "Upstream DNS query must contain exactly one question"
                );
            }

            DnsQuestion question =
                    outbound.questions().get(0);

            return new ExpectedResponse(
                    outbound.header().id(),
                    opcode(outbound.header().flags()),
                    canonicalizeName(question.name()),
                    question.type(),
                    question.qclass(),
                    outbound.edns().isPresent(),
                    outbound.edns()
                            .map(EdnsInfo::version)
                            .orElse(EdnsInfo.VERSION_ZERO)
            );
        }

        private void validate(
                DnsMessage response
        ) throws UpstreamDnsException {

            if (response.header().id() != transactionId) {
                throw mismatch("transaction ID");
            }

            if ((response.header().flags() & RESPONSE_FLAG) == 0) {
                throw mismatch("QR response flag");
            }

            if (opcode(response.header().flags()) != opcode) {
                throw mismatch("opcode");
            }

            if ((response.header().flags() & RESERVED_Z_FLAG) != 0) {
                throw mismatch("reserved Z flag");
            }

            if (response.questions().size() != 1) {
                throw mismatch("question count");
            }

            DnsQuestion question =
                    response.questions().get(0);

            if (!canonicalQuestionName.equals(
                    canonicalizeName(question.name())
            )) {
                throw mismatch("question name");
            }

            if (question.type() != questionType) {
                throw mismatch("question type");
            }

            if (question.qclass() != questionClass) {
                throw mismatch("question class");
            }

            validateEdnsAndRcode(response);
        }

        private void validateEdnsAndRcode(
                DnsMessage response
        ) throws UpstreamDnsException {

            int extendedRcode = 0;

            if (response.edns().isPresent()) {
                if (!ednsRequested) {
                    throw mismatch("unsolicited OPT record");
                }

                EdnsInfo edns = response.edns().orElseThrow();

                if (edns.version() != EdnsInfo.VERSION_ZERO
                        || edns.version() != ednsVersion) {
                    throw mismatch("EDNS version");
                }

                extendedRcode = edns.extendedRcode();
            }

            int fullRcode =
                    (extendedRcode << 4)
                            | (response.header().flags() & RCODE_MASK);

            if (fullRcode != RCODE_NOERROR
                    && fullRcode != RCODE_NXDOMAIN) {
                throw new UpstreamDnsException(
                        "Upstream DNS response used unsupported RCODE "
                                + fullRcode
                );
            }
        }

        private static int opcode(int flags) {
            return (flags & OPCODE_MASK) >>> 11;
        }

        private static String canonicalizeName(String name) {
            StringBuilder canonical = new StringBuilder(name.length());

            for (int index = 0; index < name.length(); index++) {
                char value = name.charAt(index);

                if (value >= 'A' && value <= 'Z') {
                    canonical.append((char) (value + ('a' - 'A')));
                } else {
                    canonical.append(value);
                }
            }

            return canonical.toString();
        }

        private static UpstreamDnsException mismatch(String field) {
            return new UpstreamDnsException(
                    "Upstream DNS response did not match the query "
                            + field
            );
        }
    }
}
