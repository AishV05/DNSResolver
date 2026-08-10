package com.ayushman.dns.server;

import java.net.DatagramPacket;
import java.net.DatagramSocket;

import com.ayushman.dns.protocol.DnsHeader;
import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsPacketParser;
import com.ayushman.dns.protocol.DnsPacketWriter;
import com.ayushman.dns.resolver.RecursiveResolver;

public class DnsRequestHandler implements Runnable{
    private final DatagramPacket requestPacket;
    private final DatagramSocket socket;
    private final RecursiveResolver resolver;

    public DnsRequestHandler(DatagramSocket socket, DatagramPacket requestPacket, RecursiveResolver resolver){
        this.socket = socket;
        this.requestPacket = requestPacket;
        this.resolver = resolver;
    }

    @Override
    public void run() {
        long startTime = System.currentTimeMillis();

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
            try {
                sendFormatError(requestData);
            } catch (Exception ignored) {
                // The client cannot be notified if sending the error fails.
            }

            return;
        }

        try {
            DnsMessage responseMessage = resolver.resolve(query);

            sendResponse(responseMessage);

            long duration = System.currentTimeMillis() - startTime;

            System.out.println(
                    "Handled query from "
                            + requestPacket.getAddress()
                            + " in "
                            + duration + " ms"
            );
        } catch (Exception e) {
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
                java.util.List.of(),
                java.util.List.of(),
                java.util.List.of()
        );

        sendResponse(errorResponse);
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
                        java.util.List.of(),
                        java.util.List.of(),
                        java.util.List.of(),
                        java.util.List.of()
                );

        sendResponse(errorResponse);
    }

    private void sendResponse(
            DnsMessage responseMessage
    ) throws Exception {

        byte[] response =
                DnsPacketWriter.buildResponse(responseMessage);

        DatagramPacket responsePacket =
                new DatagramPacket(
                        response,
                        response.length,
                        requestPacket.getAddress(),
                        requestPacket.getPort()
                );

        socket.send(responsePacket);
    }
}
