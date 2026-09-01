package com.ayushman.dns.server;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.Test;

public class ClientRateLimiterTest {

    @Test
    void shouldAllowBurstThenRefillTokensOverTime()
            throws Exception {

        AtomicLong now = new AtomicLong();
        ClientRateLimiter limiter = new ClientRateLimiter(
                2,
                2,
                now::get,
                10
        );
        InetAddress client = InetAddress.getByName("192.0.2.10");

        assertTrue(limiter.tryAcquire(client));
        assertTrue(limiter.tryAcquire(client));
        assertFalse(limiter.tryAcquire(client));

        now.addAndGet(TimeUnit.MILLISECONDS.toNanos(500));

        assertTrue(limiter.tryAcquire(client));
        assertFalse(limiter.tryAcquire(client));
    }

    @Test
    void shouldLimitClientsIndependently()
            throws Exception {

        ClientRateLimiter limiter = new ClientRateLimiter(
                1,
                1
        );

        assertTrue(limiter.tryAcquire(
                InetAddress.getByName("192.0.2.10")
        ));
        assertFalse(limiter.tryAcquire(
                InetAddress.getByName("192.0.2.10")
        ));
        assertTrue(limiter.tryAcquire(
                InetAddress.getByName("192.0.2.11")
        ));
    }

    @Test
    void shouldRejectInvalidConfiguration() {

        assertThrows(
                IllegalArgumentException.class,
                () -> new ClientRateLimiter(0, 1)
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> new ClientRateLimiter(1, 0)
        );
    }
}
