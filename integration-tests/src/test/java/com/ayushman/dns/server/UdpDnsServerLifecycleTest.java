package com.ayushman.dns.server;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import org.junit.jupiter.api.Test;

public class UdpDnsServerLifecycleTest {

    @Test
    void shouldStopAcceptingAndExitCleanly()
            throws Exception {

        UdpDnsServer server = new UdpDnsServer(
                ServerConfig.defaults().withPort(
                        availableUdpPort()
                )
        );
        ExecutorService executor = Executors.newSingleThreadExecutor();

        try {
            Future<?> serverTask = executor.submit(() -> {
                try {
                    server.start();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });

            waitForServerToStart(server);

            assertTrue(server.isRunning());

            server.close();
            serverTask.get(2, TimeUnit.SECONDS);

            assertFalse(server.isRunning());
        } finally {
            server.close();
            executor.shutdownNow();
        }
    }

    private int availableUdpPort()
            throws Exception {

        try (DatagramSocket socket = new DatagramSocket(
                0,
                InetAddress.getLoopbackAddress()
        )) {
            return socket.getLocalPort();
        }
    }

    private void waitForServerToStart(
            UdpDnsServer server
    ) throws Exception {

        long deadline = System.nanoTime()
                + TimeUnit.SECONDS.toNanos(1);

        while (!server.isRunning()
                && System.nanoTime() < deadline) {
            Thread.sleep(10);
        }
    }
}
