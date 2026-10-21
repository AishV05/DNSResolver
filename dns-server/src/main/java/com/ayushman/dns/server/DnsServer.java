package com.ayushman.dns.server;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import com.ayushman.dns.resolver.DnsResolver;
import com.ayushman.dns.resolver.RecursiveResolver;
import com.ayushman.dns.resolver.UpstreamDnsClient;

/** Coordinates UDP and TCP listeners as one readiness and lifecycle unit. */
public final class DnsServer implements AutoCloseable {

    private static final long STARTUP_TIMEOUT_NANOS =
            TimeUnit.SECONDS.toNanos(5);

    private final UdpDnsServer udpServer;
    private final TcpDnsServer tcpServer;
    private final ServerMetrics metrics;
    private final PolicySnapshotStore policySnapshotStore;
    private final PolicyTelemetry policyTelemetry;
    private final ExecutorService listenerThreads;
    private final Object lifecycleLock = new Object();

    private volatile boolean starting;
    private volatile boolean ready;
    private volatile boolean stopped;

    public DnsServer(
            ServerConfig config
    ) {
        this(
                config,
                createResolver(config),
                new PolicySnapshotStore(PolicySyncMode.DISABLED),
                PolicyTelemetry.forMode(PolicySyncMode.DISABLED)
        );
    }

    DnsServer(
            ServerConfig config,
            PolicySnapshotStore policySnapshotStore
    ) {
        this(
                config,
                createResolver(config),
                policySnapshotStore,
                PolicyTelemetry.forMode(policySnapshotStore == null
                        ? null
                        : policySnapshotStore.mode())
        );
    }

    DnsServer(
            ServerConfig config,
            PolicySnapshotStore policySnapshotStore,
            PolicyTelemetry policyTelemetry
    ) {
        this(
                config,
                createResolver(config),
                policySnapshotStore,
                policyTelemetry
        );
    }

    DnsServer(
            ServerConfig config,
            DnsResolver resolver
    ) {
        this(
                config,
                resolver,
                new PolicySnapshotStore(PolicySyncMode.DISABLED),
                PolicyTelemetry.forMode(PolicySyncMode.DISABLED)
        );
    }

    DnsServer(
            ServerConfig config,
            DnsResolver resolver,
            PolicySnapshotStore policySnapshotStore
    ) {
        this(
                config,
                resolver,
                policySnapshotStore,
                PolicyTelemetry.forMode(policySnapshotStore == null
                        ? null
                        : policySnapshotStore.mode())
        );
    }

    DnsServer(
            ServerConfig config,
            DnsResolver resolver,
            PolicySnapshotStore policySnapshotStore,
            PolicyTelemetry policyTelemetry
    ) {
        if (config == null
                || resolver == null
                || policySnapshotStore == null
                || policyTelemetry == null) {
            throw new IllegalArgumentException(
                    "DNS server dependencies must not be null"
            );
        }
        if (policySnapshotStore.mode() != policyTelemetry.mode()) {
            throw new IllegalArgumentException(
                    "policy store and telemetry modes must match"
            );
        }

        this.policySnapshotStore = policySnapshotStore;
        this.policyTelemetry = policyTelemetry;
        metrics = new ServerMetrics();
        DnsRequestProcessor processor = new DnsRequestProcessor(
                resolver,
                metrics,
                policySnapshotStore,
                policyTelemetry
        );
        ClientRateLimiter sharedRateLimiter = new ClientRateLimiter(
                config.requestsPerSecond(),
                config.requestBurstCapacity()
        );
        RequestAdmissionController udpAdmission =
                new RequestAdmissionController(
                        config.maxRequestBytes(),
                        sharedRateLimiter
                );
        RequestAdmissionController tcpAdmission =
                new RequestAdmissionController(
                        config.tcpMaxRequestBytes(),
                        sharedRateLimiter
                );

        udpServer = new UdpDnsServer(
                config,
                processor,
                udpAdmission,
                metrics
        );
        tcpServer = new TcpDnsServer(
                config,
                processor,
                tcpAdmission,
                metrics
        );
        listenerThreads = Executors.newFixedThreadPool(2, runnable -> {
            Thread thread = new Thread(runnable, "dns-listener");
            thread.setDaemon(false);
            return thread;
        });
    }

    public void start() throws Exception {
        synchronized (lifecycleLock) {
            if (starting || stopped) {
                throw new IllegalStateException(
                        "DNS server cannot be started again"
                );
            }
            starting = true;
        }

        Future<?> udpTask = listenerThreads.submit(() -> {
            udpServer.start();
            return null;
        });
        Future<?> tcpTask = listenerThreads.submit(() -> {
            tcpServer.start();
            return null;
        });

        try {
            awaitBothListeners(udpTask, tcpTask);
            System.out.println(
                    "DNS listeners bound on UDP and TCP port"
            );
            awaitListenerTermination(udpTask, tcpTask);
        } finally {
            close();
        }
    }

    public boolean isRunning() {
        return ready
                && listenersRunning()
                && policySnapshotStore.isReady();
    }

    public boolean isUdpRunning() {
        return udpServer.isRunning();
    }

    public boolean isTcpRunning() {
        return tcpServer.isRunning();
    }

    public ServerMetrics metrics() {
        return metrics;
    }

    PolicyTelemetry.Snapshot policyTelemetrySnapshot() {
        return policyTelemetry.snapshot(
                policySnapshotStore.snapshotStatus()
        );
    }

    @Override
    public void close() {
        stopped = true;
        ready = false;
        udpServer.close();
        tcpServer.close();
        listenerThreads.shutdownNow();
    }

    private void awaitBothListeners(
            Future<?> udpTask,
            Future<?> tcpTask
    ) throws Exception {
        long deadline = System.nanoTime() + STARTUP_TIMEOUT_NANOS;

        while (!listenersRunning()) {
            throwIfListenerFailed(udpTask, "UDP");
            throwIfListenerFailed(tcpTask, "TCP");
            if (stopped) {
                throw new IllegalStateException(
                        "DNS server stopped during startup"
                );
            }
            if (System.nanoTime() >= deadline) {
                throw new IllegalStateException(
                        "timed out while starting DNS listeners"
                );
            }
            Thread.sleep(10);
        }
        ready = true;
    }

    private void awaitListenerTermination(
            Future<?> udpTask,
            Future<?> tcpTask
    ) throws Exception {
        while (!stopped) {
            if (udpTask.isDone()) {
                throwIfListenerFailed(udpTask, "UDP");
                throw new IllegalStateException(
                        "UDP listener stopped unexpectedly"
                );
            }
            if (tcpTask.isDone()) {
                throwIfListenerFailed(tcpTask, "TCP");
                throw new IllegalStateException(
                        "TCP listener stopped unexpectedly"
                );
            }
            Thread.sleep(100);
        }
    }

    private void throwIfListenerFailed(
            Future<?> task,
            String transport
    ) throws Exception {
        if (!task.isDone()) {
            return;
        }

        try {
            task.get();
        } catch (ExecutionException failure) {
            Throwable cause = failure.getCause();
            if (cause instanceof Exception exception) {
                throw exception;
            }
            throw new IllegalStateException(
                    transport + " listener failed",
                    cause
            );
        }
    }

    private static DnsResolver createResolver(
            ServerConfig config
    ) {
        if (config == null) {
            throw new IllegalArgumentException("config must not be null");
        }

        return new RecursiveResolver(
                new UpstreamDnsClient(
                        config.upstreamTimeoutMillis(),
                        config.upstreamMaxAttempts(),
                        config.upstreamPort()
                )
        );
    }

    private boolean listenersRunning() {
        return udpServer.isRunning() && tcpServer.isRunning();
    }
}
