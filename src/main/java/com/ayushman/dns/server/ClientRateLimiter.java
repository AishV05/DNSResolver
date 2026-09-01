package com.ayushman.dns.server;

import java.net.InetAddress;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

/**
 * Thread-safe, per-client token-bucket rate limiter for UDP requests.
 */
public final class ClientRateLimiter {

    private static final long NANOS_PER_SECOND =
            TimeUnit.SECONDS.toNanos(1);

    private static final long STALE_CLIENT_NANOS =
            TimeUnit.MINUTES.toNanos(10);

    private static final long CLEANUP_INTERVAL_NANOS =
            TimeUnit.MINUTES.toNanos(1);

    private static final int DEFAULT_MAX_TRACKED_CLIENTS =
            10_000;

    private final int requestsPerSecond;
    private final int burstCapacity;
    private final int maxTrackedClients;
    private final LongSupplier nanoTime;
    private final ConcurrentHashMap<InetAddress, Bucket> buckets =
            new ConcurrentHashMap<>();
    private final AtomicLong lastCleanupNanos =
            new AtomicLong();

    public ClientRateLimiter(
            int requestsPerSecond,
            int burstCapacity
    ) {

        this(
                requestsPerSecond,
                burstCapacity,
                System::nanoTime,
                DEFAULT_MAX_TRACKED_CLIENTS
        );
    }

    ClientRateLimiter(
            int requestsPerSecond,
            int burstCapacity,
            LongSupplier nanoTime,
            int maxTrackedClients
    ) {

        if (requestsPerSecond <= 0) {
            throw new IllegalArgumentException(
                    "requestsPerSecond must be positive"
            );
        }

        if (burstCapacity <= 0) {
            throw new IllegalArgumentException(
                    "burstCapacity must be positive"
            );
        }

        if (nanoTime == null) {
            throw new IllegalArgumentException(
                    "nanoTime must not be null"
            );
        }

        if (maxTrackedClients <= 0) {
            throw new IllegalArgumentException(
                    "maxTrackedClients must be positive"
            );
        }

        this.requestsPerSecond = requestsPerSecond;
        this.burstCapacity = burstCapacity;
        this.nanoTime = nanoTime;
        this.maxTrackedClients = maxTrackedClients;
    }

    /**
     * Returns whether one request from {@code client} may proceed.
     */
    public boolean tryAcquire(
            InetAddress client
    ) {

        if (client == null) {
            return false;
        }

        long now = nanoTime.getAsLong();
        removeStaleClients(now);

        Bucket bucket = buckets.get(client);

        if (bucket == null) {
            bucket = createBucket(client, now);
        }

        return bucket != null && bucket.tryAcquire(now);
    }

    private Bucket createBucket(
            InetAddress client,
            long now
    ) {

        synchronized (buckets) {
            Bucket existing = buckets.get(client);

            if (existing != null) {
                return existing;
            }

            if (buckets.size() >= maxTrackedClients) {
                return null;
            }

            Bucket created = new Bucket(now);

            buckets.put(client, created);

            return created;
        }
    }

    private void removeStaleClients(
            long now
    ) {

        long lastCleanup = lastCleanupNanos.get();

        if (now - lastCleanup < CLEANUP_INTERVAL_NANOS
                || !lastCleanupNanos.compareAndSet(
                        lastCleanup,
                        now
                )) {
            return;
        }

        buckets.entrySet().removeIf(entry ->
                now - entry.getValue().lastSeenNanos()
                        > STALE_CLIENT_NANOS
        );
    }

    private final class Bucket {

        private double availableTokens = burstCapacity;
        private long lastRefillNanos;
        private long lastSeenNanos;

        private Bucket(long now) {

            this.lastRefillNanos = now;
            this.lastSeenNanos = now;
        }

        synchronized boolean tryAcquire(
                long now
        ) {

            long elapsedNanos = Math.max(
                    0,
                    now - lastRefillNanos
            );

            double refilledTokens =
                    elapsedNanos
                            * (double) requestsPerSecond
                            / NANOS_PER_SECOND;

            availableTokens = Math.min(
                    burstCapacity,
                    availableTokens + refilledTokens
            );

            lastRefillNanos = Math.max(
                    lastRefillNanos,
                    now
            );
            lastSeenNanos = now;

            if (availableTokens < 1) {
                return false;
            }

            availableTokens--;

            return true;
        }

        synchronized long lastSeenNanos() {
            return lastSeenNanos;
        }
    }
}
