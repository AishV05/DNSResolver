package com.ayushman.dns.server;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;

import com.ayushman.dns.protocol.DnsHeader;
import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsPacketParser;
import com.ayushman.dns.protocol.DnsPacketWriter;
import com.ayushman.dns.resolver.SimpleResolver;

public class DnsRequestHandler implements Runnable{
    private final DatagramPacket requestPacket;
    private final DatagramSocket socket;
    private final SimpleResolver resolver;

    public DnsRequestHandler(DatagramSocket socket, DatagramPacket requestPacket, SimpleResolver resolver){
        this.socket = socket;
        this.requestPacket = requestPacket;
        this.resolver = resolver;
    }

    @Override
    public void run() {
        long startTime = System.currentTimeMillis();

        try {

            byte[] requestData = new byte[requestPacket.getLength()];
            System.arraycopy(
                    requestPacket.getData(),
                    0,
                    requestData,
                    0,
                    requestPacket.getLength()
            );

            // Parse
            DnsMessage query = DnsPacketParser.parse(requestData);

            // Resolve
            DnsMessage responseMessage = resolver.resolve(query);

            // Serialize
            byte[] responseData =
                    DnsPacketWriter.buildResponse(responseMessage);

            // Send response
            DatagramPacket responsePacket =
                    new DatagramPacket(
                            responseData,
                            responseData.length,
                            requestPacket.getAddress(),
                            requestPacket.getPort()
                    );

            socket.send(responsePacket);

            long duration = System.currentTimeMillis() - startTime;

            System.out.println(
                    "Handled query from "
                            + requestPacket.getAddress()
                            + " in "
                            + duration + " ms"
            );

        } catch (IOException e) {

            System.err.println("Error handling request: "
                    + e.getMessage());

            try {
                sendServFail();
            } catch (Exception ignored) {}
        }
    }

    private void sendServFail() throws Exception {

        byte[] requestData = new byte[requestPacket.getLength()];
        System.arraycopy(
                requestPacket.getData(),
                0,
                requestData,
                0,
                requestPacket.getLength()
        );

        DnsMessage query = DnsPacketParser.parse(requestData);

        int flags = 0x8182; 

        DnsHeader header = new DnsHeader(
                query.header().id(),
                flags,
                query.header().qdCount(),
                0,
                0,
                0
        );

        DnsMessage errorResponse =
                new DnsMessage(header, query.questions(), java.util.List.of());

        byte[] response =
                DnsPacketWriter.buildResponse(errorResponse);

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