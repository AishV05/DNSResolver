package com.ayushman.dns.server;

import java.net.DatagramPacket;
import java.net.DatagramSocket;

import com.ayushman.dns.resolver.DnsResolver;

/** Sends one UDP request through the shared DNS request processor. */
public class DnsRequestHandler implements Runnable {

    private final DatagramPacket requestPacket;
    private final DatagramSocket socket;
    private final DnsRequestProcessor processor;

    public DnsRequestHandler(
            DatagramSocket socket,
            DatagramPacket requestPacket,
            DnsResolver resolver
    ) {
        this(socket, requestPacket, resolver, new ServerMetrics());
    }

    DnsRequestHandler(
            DatagramSocket socket,
            DatagramPacket requestPacket,
            DnsResolver resolver,
            ServerMetrics metrics
    ) {
        this(
                socket,
                requestPacket,
                new DnsRequestProcessor(resolver, metrics)
        );
    }

    DnsRequestHandler(
            DatagramSocket socket,
            DatagramPacket requestPacket,
            DnsRequestProcessor processor
    ) {
        if (socket == null || requestPacket == null || processor == null) {
            throw new IllegalArgumentException(
                    "UDP handler dependencies must not be null"
            );
        }

        this.socket = socket;
        this.requestPacket = requestPacket;
        this.processor = processor;
    }

    @Override
    public void run() {
        byte[] requestData = new byte[requestPacket.getLength()];
        System.arraycopy(
                requestPacket.getData(),
                requestPacket.getOffset(),
                requestData,
                0,
                requestPacket.getLength()
        );

        try {
            byte[] response = processor.process(
                    requestData,
                    DnsTransport.UDP
            );
            DatagramPacket responsePacket = new DatagramPacket(
                    response,
                    response.length,
                    requestPacket.getAddress(),
                    requestPacket.getPort()
            );
            socket.send(responsePacket);
        } catch (Exception ignored) {
            // The client cannot be notified when serialization or send fails.
        }
    }
}
