package com.ayushman.dns.server;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.util.List;

import com.ayushman.dns.protocol.DnsHeader;
import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsPacketParser;
import com.ayushman.dns.protocol.DnsPacketWriter;
import com.ayushman.dns.protocol.EdnsInfo;
import com.ayushman.dns.resolver.RecursiveResolver;

public class DnsRequestHandler implements Runnable {

    private static final int DEFAULT_UDP_PAYLOAD_SIZE = 512;

    private static final int SERVER_UDP_PAYLOAD_SIZE = 1_232;

    private static final int BADVERS_EXTENDED_RCODE = 1;

    private static final int TRUNCATED_FLAG = 0x0200;

    private final DatagramPacket requestPacket;
    private final DatagramSocket socket;
    private final RecursiveResolver resolver;
    private final ServerMetrics metrics;

    public DnsRequestHandler(DatagramSocket socket, DatagramPacket requestPacket, RecursiveResolver resolver){
        this(socket, requestPacket, resolver, new ServerMetrics());
    }

    DnsRequestHandler(
            DatagramSocket socket,
            DatagramPacket requestPacket,
            RecursiveResolver resolver,
            ServerMetrics metrics
    ) {
        this.socket = socket;
        this.requestPacket = requestPacket;
        this.resolver = resolver;
        this.metrics = metrics;
    }

    @Override
    public void run() {
        long startTime = System.nanoTime();

        byte[] requestData = new byte[requestPacket.getLength()];
        System.arraycopy(
                requestPacket.getData(),
                requestPacket.getOffset(),
                requestData,
                0,
                requestPacket.getLength()
        );

        DnsMessage query;

        try {
            query = DnsPacketParser.parse(requestData);
        } catch (Exception e) {
            metrics.recordMalformedRequest();

            try {
                sendFormatError(requestData);
            } catch (Exception ignored) {
                // The client cannot be notified if sending the error fails.
            }

            return;
        }

        if (hasUnsupportedEdnsVersion(query)) {
            metrics.recordUnsupportedEdnsVersion();

            try {
                sendBadVersion(query);
            } catch (Exception ignored) {
                // The client cannot be notified if sending the error fails.
            }

            return;
        }

        try {
            DnsMessage responseMessage = resolver.resolve(query);

            sendResponseForQuery(responseMessage, query);

            long duration = System.nanoTime() - startTime;

            metrics.recordResolvedRequest(duration);

            System.out.println(
                    "Handled query from "
                            + requestPacket.getAddress()
                            + " in "
                            + duration / 1_000_000 + " ms"
            );
        } catch (Exception e) {
            metrics.recordResolverFailure();

            try {
                sendServFail(query);
            } catch (Exception ignored) {
                // The client cannot be notified if sending the error fails.
            }
        }
    }

    private void sendServFail(
            DnsMessage query
    ) throws Exception {

        int flags =
                0x8000
                        | (query.header().flags() & 0x0100)
                        | 0x0080
                        | 0x0002;

        DnsHeader header = new DnsHeader(
                query.header().id(),
                flags,
                query.header().qdCount(),
                0,
                0,
                0
        );

        DnsMessage errorResponse =
        new DnsMessage(
                header,
                query.questions(),
                List.of(),
                List.of(),
                List.of()
        );

        sendResponseForQuery(errorResponse, query);
    }

    private void sendBadVersion(
            DnsMessage query
    ) throws Exception {

        int flags =
                0x8000
                        | (query.header().flags() & 0x0100)
                        | 0x0080;

        DnsMessage errorResponse =
                new DnsMessage(
                        new DnsHeader(
                                query.header().id(),
                                flags,
                                query.questions().size(),
                                0,
                                0,
                                0
                        ),
                        query.questions(),
                        List.of(),
                        List.of(),
                        List.of(),
                        new EdnsInfo(
                                responsePayloadSize(query),
                                BADVERS_EXTENDED_RCODE,
                                EdnsInfo.VERSION_ZERO,
                                0,
                                new byte[0]
                        )
                );

        sendPreparedResponse(
                errorResponse,
                responsePayloadSize(query)
        );
    }

    private void sendFormatError(
            byte[] requestData
    ) throws Exception {

        int id = 0;
        int requestFlags = 0;

        if (requestData.length >= 2) {
            id = ((requestData[0] & 0xFF) << 8)
                    | (requestData[1] & 0xFF);
        }

        if (requestData.length >= 4) {
            requestFlags =
                    ((requestData[2] & 0xFF) << 8)
                            | (requestData[3] & 0xFF);
        }

        int flags =
                0x8000
                        | (requestFlags & 0x0100)
                        | 0x0080
                        | 0x0001;

        DnsMessage errorResponse =
                new DnsMessage(
                        new DnsHeader(
                                id,
                                flags,
                                0,
                                0,
                                0,
                                0
                        ),
                        List.of(),
                        List.of(),
                        List.of(),
                        List.of()
                );

        sendPreparedResponse(
                errorResponse,
                DEFAULT_UDP_PAYLOAD_SIZE
        );
    }

    private boolean hasUnsupportedEdnsVersion(
            DnsMessage query
    ) {

        return query.edns()
                .map(
                        edns -> edns.version()
                                != EdnsInfo.VERSION_ZERO
                )
                .orElse(false);
    }

    private void sendResponseForQuery(
            DnsMessage resolverResponse,
            DnsMessage clientQuery
    ) throws Exception {

        DnsMessage response =
                withEdnsForClient(
                        resolverResponse,
                        clientQuery
                );

        sendPreparedResponse(
                response,
                responsePayloadSize(clientQuery)
        );
    }

    private DnsMessage withEdnsForClient(
            DnsMessage resolverResponse,
            DnsMessage clientQuery
    ) {

        EdnsInfo responseEdns =
                clientQuery.edns()
                        .map(ignored -> new EdnsInfo(
                                responsePayloadSize(clientQuery),
                                0,
                                EdnsInfo.VERSION_ZERO,
                                0,
                                new byte[0]
                        ))
                        .orElse(null);

        return new DnsMessage(
                resolverResponse.header(),
                resolverResponse.questions(),
                resolverResponse.answers(),
                resolverResponse.authorities(),
                resolverResponse.additionals(),
                responseEdns
        );
    }

    private int responsePayloadSize(
            DnsMessage query
    ) {

        return query.edns()
                .map(EdnsInfo::effectiveUdpPayloadSize)
                .map(size -> Math.min(
                        size,
                        SERVER_UDP_PAYLOAD_SIZE
                ))
                .orElse(DEFAULT_UDP_PAYLOAD_SIZE);
    }

    private void sendPreparedResponse(
            DnsMessage responseMessage,
            int payloadSize
    ) throws Exception {

        byte[] response =
                DnsPacketWriter.buildResponse(responseMessage);

        if (response.length > payloadSize) {
            response = DnsPacketWriter.buildResponse(
                    truncatedResponse(responseMessage)
            );
        }

        DatagramPacket responsePacket =
                new DatagramPacket(
                        response,
                        response.length,
                        requestPacket.getAddress(),
                        requestPacket.getPort()
                );

        socket.send(responsePacket);
    }

    private DnsMessage truncatedResponse(
            DnsMessage response
    ) {

        DnsHeader header = response.header();

        DnsHeader truncatedHeader =
                new DnsHeader(
                        header.id(),
                        header.flags() | TRUNCATED_FLAG,
                        response.questions().size(),
                        0,
                        0,
                        0
                );

        return new DnsMessage(
                truncatedHeader,
                response.questions(),
                List.of(),
                List.of(),
                List.of(),
                response.edns().orElse(null)
        );
    }
}
