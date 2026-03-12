package com.ayushman.dns.server;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import com.ayushman.dns.resolver.SimpleResolver;

public class UdpDnsServer {

    private final int port;
    private final SimpleResolver resolver;
    private final ExecutorService threadPool;

    public UdpDnsServer(int port) {
        this.port = port;
        this.resolver = new SimpleResolver();
        this.threadPool = Executors.newFixedThreadPool(10);
    }

    public void start() throws Exception {

        DatagramSocket socket = new DatagramSocket(port);
        System.out.println("DNS Server listening on port " + port);

        while (true) {

            byte[] buffer = new byte[512];

            DatagramPacket requestPacket =
                    new DatagramPacket(buffer, buffer.length);

            socket.receive(requestPacket);

            threadPool.submit(
                    new DnsRequestHandler(
                            socket,
                            requestPacket,
                            resolver
                    )
            );
        }
    }
}