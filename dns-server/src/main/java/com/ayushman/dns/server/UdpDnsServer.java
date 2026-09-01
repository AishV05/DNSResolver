package com.ayushman.dns.server;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import com.ayushman.dns.resolver.RecursiveResolver;
import com.ayushman.dns.resolver.UpstreamDnsClient;

public class UdpDnsServer implements AutoCloseable {

    private static final int RECEIVE_TIMEOUT_MILLIS = 1_000;

    private final int port;
    private final RecursiveResolver resolver;
    private final ExecutorService threadPool;
    private final RequestAdmissionController admissionController;
    private final ServerMetrics metrics;
    private final int metricsIntervalSeconds;
    private final Object lifecycleLock = new Object();

    private volatile DatagramSocket socket;
    private volatile ScheduledExecutorService metricsReporter;
    private volatile boolean running;
    private volatile boolean stopped;

    public UdpDnsServer(int port) {
        this(ServerConfig.defaults().withPort(port));
    }

    public UdpDnsServer(
            int port,
            RecursiveResolver resolver
    ) {

        this(
                ServerConfig.defaults().withPort(port),
                resolver,
                new RequestAdmissionController(
                        ServerConfig.defaults().maxRequestBytes(),
                        new ClientRateLimiter(
                                ServerConfig.defaults()
                                        .requestsPerSecond(),
                                ServerConfig.defaults()
                                        .requestBurstCapacity()
                        )
                ),
                new ServerMetrics()
        );
    }

    public UdpDnsServer(
            ServerConfig config
    ) {

        this(
                config,
                new RecursiveResolver(
                        new UpstreamDnsClient(
                                config.upstreamTimeoutMillis(),
                                config.upstreamMaxAttempts(),
                                config.upstreamPort()
                        )
                ),
                new RequestAdmissionController(
                        config.maxRequestBytes(),
                        new ClientRateLimiter(
                                config.requestsPerSecond(),
                                config.requestBurstCapacity()
                        )
                ),
                new ServerMetrics()
        );
    }

    UdpDnsServer(
            ServerConfig config,
            RecursiveResolver resolver,
            RequestAdmissionController admissionController,
            ServerMetrics metrics
    ) {

        if (config == null) {
            throw new IllegalArgumentException(
                    "config must not be null"
            );
        }

        if (resolver == null) {
            throw new IllegalArgumentException(
                    "resolver must not be null"
            );
        }

        if (admissionController == null) {
            throw new IllegalArgumentException(
                    "admissionController must not be null"
            );
        }

        if (metrics == null) {
            throw new IllegalArgumentException(
                    "metrics must not be null"
            );
        }

        this.port = config.port();
        this.resolver = resolver;
        this.admissionController = admissionController;
        this.metrics = metrics;
        this.metricsIntervalSeconds = config.metricsIntervalSeconds();
        this.threadPool = new ThreadPoolExecutor(
                config.workerThreads(),
                config.workerThreads(),
                0,
                TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(
                        config.workerQueueCapacity()
                ),
                new ThreadPoolExecutor.AbortPolicy()
        );
    }

    public void start() throws Exception {

        DatagramSocket serverSocket = openSocket();

        System.out.println(
                "DNS Server listening on port " + port
        );

        startMetricsReporter();

        try {
            receiveRequests(serverSocket);
        } finally {
            finishShutdown(serverSocket);
        }
    }

    public boolean isRunning() {
        return running;
    }

    @Override
    public void close() {
        running = false;
        stopped = true;

        stopMetricsReporter();
        stopWorkers();
    }

    public ServerMetrics metrics() {
        return metrics;
    }

    private DatagramSocket openSocket()
            throws SocketException {

        synchronized (lifecycleLock) {
            if (running || socket != null || stopped) {
                throw new IllegalStateException(
                        "DNS server cannot be started again"
                );
            }

            DatagramSocket serverSocket = new DatagramSocket(port);
            serverSocket.setSoTimeout(RECEIVE_TIMEOUT_MILLIS);

            socket = serverSocket;
            running = true;

            return serverSocket;
        }
    }

    private void receiveRequests(
            DatagramSocket serverSocket
    ) throws Exception {

        while (running) {

            byte[] buffer = new byte[
                    admissionController.receiveBufferSize()
            ];

            DatagramPacket requestPacket =
                    new DatagramPacket(
                            buffer,
                            buffer.length
                    );

            try {
                serverSocket.receive(requestPacket);
            } catch (SocketTimeoutException ignored) {
                continue;
            } catch (SocketException e) {
                if (!running) {
                    return;
                }

                throw e;
            }

            metrics.recordReceivedRequest();

            RequestAdmissionController.Decision decision =
                    admissionController.decide(requestPacket);

            if (decision == RequestAdmissionController
                    .Decision.OVERSIZED) {
                metrics.recordOversizedDrop();
                continue;
            }

            if (decision == RequestAdmissionController
                    .Decision.RATE_LIMITED) {
                metrics.recordRateLimitedDrop();
                continue;
            }

            metrics.recordAdmittedRequest();

            try {
                threadPool.execute(
                        new DnsRequestHandler(
                                serverSocket,
                                requestPacket,
                                resolver,
                                metrics
                        )
                );
            } catch (RejectedExecutionException ignored) {
                metrics.recordQueueFullDrop();
                // Dropping protects the bounded worker queue under load.
            }
        }
    }

    private void startMetricsReporter() {
        ScheduledExecutorService reporter =
                Executors.newSingleThreadScheduledExecutor(runnable -> {
                    Thread thread = new Thread(
                            runnable,
                            "dns-metrics"
                    );
                    thread.setDaemon(true);
                    return thread;
                });

        metricsReporter = reporter;

        reporter.scheduleAtFixedRate(
                this::logMetrics,
                metricsIntervalSeconds,
                metricsIntervalSeconds,
                TimeUnit.SECONDS
        );
    }

    private void finishShutdown(
            DatagramSocket serverSocket
    ) {

        running = false;
        stopped = true;

        stopWorkers();

        if (!serverSocket.isClosed()) {
            serverSocket.close();
        }

        synchronized (lifecycleLock) {
            if (socket == serverSocket) {
                socket = null;
            }
        }

        stopMetricsReporter();
    }

    private void stopMetricsReporter() {
        ScheduledExecutorService reporter = metricsReporter;

        if (reporter != null) {
            reporter.shutdownNow();
            metricsReporter = null;
        }
    }

    private void stopWorkers() {
        threadPool.shutdown();

        try {
            if (!threadPool.awaitTermination(5, TimeUnit.SECONDS)) {
                threadPool.shutdownNow();
            }
        } catch (InterruptedException e) {
            threadPool.shutdownNow();
            Thread.currentThread().interrupt();
        }
    }

    private void logMetrics() {
        ServerMetrics.Snapshot snapshot = metrics.snapshot();

        System.out.printf(
                "metrics received=%d admitted=%d dropped_oversized=%d "
                        + "dropped_rate_limited=%d dropped_queue_full=%d "
                        + "malformed=%d bad_edns_version=%d resolved=%d "
                        + "resolver_failures=%d avg_handled_ms=%.2f%n",
                snapshot.receivedRequests(),
                snapshot.admittedRequests(),
                snapshot.oversizedDrops(),
                snapshot.rateLimitedDrops(),
                snapshot.queueFullDrops(),
                snapshot.malformedRequests(),
                snapshot.unsupportedEdnsVersions(),
                snapshot.resolvedRequests(),
                snapshot.resolverFailures(),
                snapshot.averageHandledMillis()
        );
    }

    public static void main(String[] args)
            throws Exception {

        Main.main(args);
    }
}
