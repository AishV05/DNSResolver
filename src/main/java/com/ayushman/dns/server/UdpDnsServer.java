package com.ayushman.dns.server;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import com.ayushman.dns.resolver.RecursiveResolver;
import com.ayushman.dns.resolver.UpstreamDnsClient;

public class UdpDnsServer {

    private final int port;
    private final RecursiveResolver resolver;
    private final ExecutorService threadPool;
    private final RequestAdmissionController admissionController;
    private final ServerMetrics metrics;
    private final int metricsIntervalSeconds;

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

        DatagramSocket socket =
                new DatagramSocket(port);

        System.out.println(
                "DNS Server listening on port " + port
        );

        ScheduledExecutorService metricsReporter =
                Executors.newSingleThreadScheduledExecutor(runnable -> {
                    Thread thread = new Thread(
                            runnable,
                            "dns-metrics"
                    );
                    thread.setDaemon(true);
                    return thread;
                });

        metricsReporter.scheduleAtFixedRate(
                this::logMetrics,
                metricsIntervalSeconds,
                metricsIntervalSeconds,
                TimeUnit.SECONDS
        );

        while (true) {

            byte[] buffer = new byte[
                    admissionController.receiveBufferSize()
            ];

            DatagramPacket requestPacket =
                    new DatagramPacket(
                            buffer,
                            buffer.length
                    );

            socket.receive(requestPacket);

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
                                socket,
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

    public ServerMetrics metrics() {
        return metrics;
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

        new UdpDnsServer(ServerConfig.fromSystem()).start();
    }
}
