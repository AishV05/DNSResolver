package com.ayushman.dns.server;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.Set;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.Semaphore;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Bounded client-facing DNS-over-TCP listener using RFC length framing.
 */
public final class TcpDnsServer implements AutoCloseable {

    private static final int ACCEPT_TIMEOUT_MILLIS = 1_000;

    private final int port;
    private final int acceptBacklog;
    private final int idleTimeoutMillis;
    private final int messageTimeoutMillis;
    private final int maxQueriesPerConnection;
    private final int maxConnectionsPerClient;
    private final DnsRequestProcessor processor;
    private final RequestAdmissionController admissionController;
    private final ServerMetrics metrics;
    private final ThreadPoolExecutor connectionWorkers;
    private final ScheduledThreadPoolExecutor deadlineExecutor;
    private final Semaphore connectionPermits;
    private final ConcurrentHashMap<InetAddress, Integer> clientConnections =
            new ConcurrentHashMap<>();
    private final Set<Socket> activeSockets = ConcurrentHashMap.newKeySet();
    private final Object lifecycleLock = new Object();

    private volatile ServerSocket serverSocket;
    private volatile boolean running;
    private volatile boolean stopped;

    TcpDnsServer(
            ServerConfig config,
            DnsRequestProcessor processor,
            RequestAdmissionController admissionController,
            ServerMetrics metrics
    ) {
        if (config == null
                || processor == null
                || admissionController == null
                || metrics == null) {
            throw new IllegalArgumentException(
                    "TCP server dependencies must not be null"
            );
        }

        this.port = config.port();
        this.acceptBacklog = config.tcpAcceptBacklog();
        this.idleTimeoutMillis = config.tcpIdleTimeoutMillis();
        this.messageTimeoutMillis = config.tcpMessageTimeoutMillis();
        this.maxQueriesPerConnection =
                config.tcpMaxQueriesPerConnection();
        this.maxConnectionsPerClient =
                config.tcpMaxConnectionsPerClient();
        this.processor = processor;
        this.admissionController = admissionController;
        this.metrics = metrics;
        this.connectionPermits = new Semaphore(
                config.tcpMaxConnections(),
                true
        );
        this.connectionWorkers = new ThreadPoolExecutor(
                config.workerThreads(),
                config.workerThreads(),
                0,
                TimeUnit.MILLISECONDS,
                new ArrayBlockingQueue<>(config.workerQueueCapacity()),
                runnable -> {
                    Thread thread = new Thread(runnable, "dns-tcp-worker");
                    thread.setDaemon(true);
                    return thread;
                },
                new ThreadPoolExecutor.AbortPolicy()
        );
        this.deadlineExecutor = new ScheduledThreadPoolExecutor(
                1,
                runnable -> {
                    Thread thread = new Thread(runnable, "dns-tcp-deadline");
                    thread.setDaemon(true);
                    return thread;
                }
        );
        this.deadlineExecutor.setRemoveOnCancelPolicy(true);
    }

    public void start() throws Exception {
        ServerSocket listener = openSocket();

        System.out.println("DNS TCP listener on port " + port);

        try {
            acceptConnections(listener);
        } finally {
            finishShutdown(listener);
        }
    }

    public boolean isRunning() {
        return running;
    }

    @Override
    public void close() {
        running = false;
        stopped = true;

        ServerSocket listener = serverSocket;
        if (listener != null) {
            closeQuietly(listener);
        }
        activeSockets.forEach(TcpDnsServer::closeQuietly);
        stopWorkers();
    }

    private ServerSocket openSocket()
            throws IOException {
        synchronized (lifecycleLock) {
            if (running || serverSocket != null || stopped) {
                throw new IllegalStateException(
                        "TCP DNS server cannot be started again"
                );
            }

            ServerSocket listener = new ServerSocket();
            boolean bound = false;
            try {
                listener.setReuseAddress(true);
                listener.bind(new InetSocketAddress(port), acceptBacklog);
                listener.setSoTimeout(ACCEPT_TIMEOUT_MILLIS);
                serverSocket = listener;
                running = true;
                bound = true;
                return listener;
            } finally {
                if (!bound) {
                    closeQuietly(listener);
                }
            }
        }
    }

    private void acceptConnections(
            ServerSocket listener
    ) throws IOException {
        while (running) {
            Socket connection;
            try {
                connection = listener.accept();
            } catch (SocketTimeoutException ignored) {
                continue;
            } catch (SocketException closed) {
                if (!running) {
                    return;
                }
                throw closed;
            }

            configure(connection);
            admitConnection(connection);
        }
    }

    private void configure(
            Socket connection
    ) throws SocketException {
        connection.setTcpNoDelay(true);
        connection.setKeepAlive(false);
        connection.setSoTimeout(idleTimeoutMillis);
    }

    private void admitConnection(
            Socket connection
    ) {
        InetAddress client = connection.getInetAddress();
        if (!connectionPermits.tryAcquire()) {
            metrics.recordTcpConnectionLimitRejection();
            closeQuietly(connection);
            return;
        }

        if (!acquireClientConnection(client)) {
            connectionPermits.release();
            metrics.recordTcpConnectionLimitRejection();
            closeQuietly(connection);
            return;
        }

        activeSockets.add(connection);
        metrics.recordTcpConnectionAccepted();

        try {
            connectionWorkers.execute(() -> {
                try {
                    handleConnection(connection);
                } finally {
                    releaseConnection(connection, client);
                }
            });
        } catch (RejectedExecutionException rejected) {
            metrics.recordTcpConnectionQueueRejection();
            releaseConnection(connection, client);
        }
    }

    private boolean acquireClientConnection(
            InetAddress client
    ) {
        AtomicBoolean acquired = new AtomicBoolean(false);
        clientConnections.compute(client, (ignored, current) -> {
            int count = current == null ? 0 : current;
            if (count >= maxConnectionsPerClient) {
                return current;
            }
            acquired.set(true);
            return count + 1;
        });
        return acquired.get();
    }

    private void releaseConnection(
            Socket connection,
            InetAddress client
    ) {
        closeQuietly(connection);
        activeSockets.remove(connection);
        clientConnections.computeIfPresent(client, (ignored, count) ->
                count <= 1 ? null : count - 1
        );
        connectionPermits.release();
        metrics.recordTcpConnectionClosed();
    }

    private void handleConnection(
            Socket connection
    ) {
        try (connection;
                InputStream input = new BufferedInputStream(
                        connection.getInputStream()
                );
                OutputStream output = new BufferedOutputStream(
                        connection.getOutputStream()
                )) {
            for (int queryCount = 0;
                    running && queryCount < maxQueriesPerConnection;
                    queryCount++) {
                byte[] request = readFrame(connection, input);
                if (request == null) {
                    return;
                }

                metrics.recordReceivedRequest(DnsTransport.TCP);
                RequestAdmissionController.Decision decision =
                        admissionController.decide(
                                connection.getInetAddress(),
                                request.length
                        );
                if (decision == RequestAdmissionController.Decision.OVERSIZED) {
                    metrics.recordOversizedDrop();
                    return;
                }
                if (decision
                        == RequestAdmissionController.Decision.RATE_LIMITED) {
                    metrics.recordRateLimitedDrop();
                    return;
                }

                metrics.recordAdmittedRequest(DnsTransport.TCP);
                byte[] response = processor.process(
                        request,
                        DnsTransport.TCP
                );
                writeFrame(connection, output, response);
            }
        } catch (SocketTimeoutException timeout) {
            metrics.recordTcpConnectionTimeout();
        } catch (EOFException truncatedFrame) {
            metrics.recordTcpProtocolError();
        } catch (SocketException closed) {
            if (running && !connection.isClosed()) {
                metrics.recordTcpProtocolError();
            }
        } catch (IOException ioFailure) {
            if (running) {
                metrics.recordTcpProtocolError();
            }
        } catch (Exception processingFailure) {
            metrics.recordTcpProtocolError();
        }
    }

    private byte[] readFrame(
            Socket connection,
            InputStream input
    ) throws IOException {
        connection.setSoTimeout(idleTimeoutMillis);
        int high = input.read();
        if (high < 0) {
            return null;
        }

        long deadline = System.nanoTime()
                + TimeUnit.MILLISECONDS.toNanos(messageTimeoutMillis);
        int low = readByteBefore(connection, input, deadline);
        int length = (high << 8) | low;

        if (length == 0) {
            throw new EOFException("zero-length DNS-over-TCP frame");
        }

        byte[] request = new byte[length];
        readFullyBefore(connection, input, request, deadline);
        return request;
    }

    private int readByteBefore(
            Socket connection,
            InputStream input,
            long deadline
    ) throws IOException {
        setRemainingTimeout(connection, deadline);
        int value = input.read();
        if (value < 0) {
            throw new EOFException("truncated DNS-over-TCP length prefix");
        }
        return value;
    }

    private void readFullyBefore(
            Socket connection,
            InputStream input,
            byte[] destination,
            long deadline
    ) throws IOException {
        int offset = 0;
        while (offset < destination.length) {
            setRemainingTimeout(connection, deadline);
            int count = input.read(
                    destination,
                    offset,
                    destination.length - offset
            );
            if (count < 0) {
                throw new EOFException("truncated DNS-over-TCP message");
            }
            offset += count;
        }
    }

    private void writeFrame(
            Socket connection,
            OutputStream output,
            byte[] response
    ) throws IOException {
        if (response.length == 0 || response.length > 65_535) {
            throw new IOException("invalid DNS-over-TCP response length");
        }

        AtomicBoolean expired = new AtomicBoolean(false);
        ScheduledFuture<?> deadline = deadlineExecutor.schedule(() -> {
            expired.set(true);
            closeQuietly(connection);
        }, messageTimeoutMillis, TimeUnit.MILLISECONDS);
        try {
            output.write((response.length >>> 8) & 0xFF);
            output.write(response.length & 0xFF);
            output.write(response);
            output.flush();
        } catch (SocketException writeTimeout) {
            if (expired.get()) {
                throw new SocketTimeoutException(
                        "DNS-over-TCP response write timed out"
                );
            }
            throw writeTimeout;
        } finally {
            deadline.cancel(false);
        }
    }

    private void setRemainingTimeout(
            Socket connection,
            long deadline
    ) throws SocketException, SocketTimeoutException {
        long remainingNanos = deadline - System.nanoTime();
        if (remainingNanos <= 0) {
            throw new SocketTimeoutException(
                    "DNS-over-TCP request frame timed out"
            );
        }
        long remainingMillis = Math.max(
                1,
                TimeUnit.NANOSECONDS.toMillis(remainingNanos)
        );
        connection.setSoTimeout((int) Math.min(
                Integer.MAX_VALUE,
                remainingMillis
        ));
    }

    private void finishShutdown(
            ServerSocket listener
    ) {
        running = false;
        stopped = true;
        closeQuietly(listener);
        activeSockets.forEach(TcpDnsServer::closeQuietly);
        stopWorkers();
        synchronized (lifecycleLock) {
            if (serverSocket == listener) {
                serverSocket = null;
            }
        }
    }

    private void stopWorkers() {
        connectionWorkers.shutdown();
        try {
            if (!connectionWorkers.awaitTermination(5, TimeUnit.SECONDS)) {
                connectionWorkers.shutdownNow();
            }
        } catch (InterruptedException interrupted) {
            connectionWorkers.shutdownNow();
            Thread.currentThread().interrupt();
        }
        deadlineExecutor.shutdownNow();
    }

    private static void closeQuietly(
            AutoCloseable closeable
    ) {
        try {
            closeable.close();
        } catch (Exception ignored) {
            // Shutdown is best effort and idempotent.
        }
    }
}
