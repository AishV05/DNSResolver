package com.ayushman.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.DatagramPacket;
import java.net.InetAddress;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;

public class RequestAdmissionControllerTest {

    @Test
    void shouldRejectOversizedPacketsBeforeRateLimiting()
            throws Exception {

        RequestAdmissionController controller =
                new RequestAdmissionController(
                        20,
                        new ClientRateLimiter(1, 1)
                );

        DatagramPacket oversized = packet(
                21,
                "192.0.2.10"
        );

        assertFalse(controller.allow(oversized));
        assertEquals(21, controller.receiveBufferSize());
    }

    @Test
    void shouldRateLimitAdmittedPacketsPerClient()
            throws Exception {

        AtomicLong now = new AtomicLong();
        RequestAdmissionController controller =
                new RequestAdmissionController(
                        20,
                        new ClientRateLimiter(1, 1, now::get, 10)
                );

        assertTrue(controller.allow(packet(20, "192.0.2.10")));
        assertFalse(controller.allow(packet(20, "192.0.2.10")));
        assertTrue(controller.allow(packet(20, "192.0.2.11")));
    }

    private DatagramPacket packet(
            int length,
            String address
    ) throws Exception {

        return new DatagramPacket(
                new byte[length],
                length,
                InetAddress.getByName(address),
                53
        );
    }
}
