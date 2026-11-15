package com.ayushman.dns.server;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.DoubleSupplier;

import com.ayushman.dns.fleet.ResolverPolicyMode;
import com.ayushman.dns.fleet.ResolverPolicySyncState;
import com.ayushman.dns.fleet.ResolverRuntimeReport;
import com.ayushman.dns.fleet.ResolverSessionLease;
import com.ayushman.dns.fleet.ResolverSessionStart;

/**
 * Establishes a server-issued resolver session and reports policy state from
 * a background loop. No control-plane I/O occurs on a DNS query thread.
 */
public final class ResolverFleetReporter implements AutoCloseable {

    private static final String JSON_CONTENT_TYPE = "application/json";

    private final ResolverReportingConfig config;
    private final PolicySnapshotStore policyStore;
    private final PolicyTelemetry policyTelemetry;
    private final ResolverReportingTelemetry reportingTelemetry;
    private final HttpClient httpClient;
    private final ScheduledExecutorService scheduler;
    private final DoubleSupplier jitterSource;
    private final UUID bootId;
    private final AtomicBoolean started = new AtomicBoolean();
    private final AtomicBoolean closed = new AtomicBoolean();
    private final AtomicBoolean fenced = new AtomicBoolean();

    private ResolverSessionLease lease;
    private ResolverRuntimeReport pendingReport;
    private long nextSequence = 1;
    private int consecutiveFailures;

    public ResolverFleetReporter(
            ResolverReportingConfig config,
            PolicySnapshotStore policyStore,
            PolicyTelemetry policyTelemetry
    ) {
        this(
                config,
                policyStore,
                policyTelemetry,
                createTelemetry(config)
        );
    }

    ResolverFleetReporter(
            ResolverReportingConfig config,
            PolicySnapshotStore policyStore,
            PolicyTelemetry policyTelemetry,
            ResolverReportingTelemetry reportingTelemetry
    ) {
        this(
                config,
                policyStore,
                policyTelemetry,
                reportingTelemetry,
                createHttpClient(config),
                createScheduler(),
                Math::random,
                UUID.randomUUID()
        );
    }

    ResolverFleetReporter(
            ResolverReportingConfig config,
            PolicySnapshotStore policyStore,
            PolicyTelemetry policyTelemetry,
            ResolverReportingTelemetry reportingTelemetry,
            HttpClient httpClient,
            ScheduledExecutorService scheduler,
            DoubleSupplier jitterSource,
            UUID bootId
    ) {
        if (config == null
                || policyStore == null
                || policyTelemetry == null
                || reportingTelemetry == null
                || httpClient == null
                || scheduler == null
                || jitterSource == null
                || bootId == null) {
            throw new IllegalArgumentException(
                    "resolver reporter dependencies must not be null"
            );
        }
        if (policyStore.mode() != policyTelemetry.mode()) {
            throw new IllegalArgumentException(
                    "policy store and telemetry modes must match"
            );
        }
        if (bootId.equals(new UUID(0, 0))) {
            throw new IllegalArgumentException("bootId must not be nil");
        }
        this.config = config;
        this.policyStore = policyStore;
        this.policyTelemetry = policyTelemetry;
        this.reportingTelemetry = reportingTelemetry;
        this.httpClient = httpClient;
        this.scheduler = scheduler;
        this.jitterSource = jitterSource;
        this.bootId = bootId;
    }

    public void start() {
        if (closed.get()) {
            throw new IllegalStateException(
                    "closed resolver reporter cannot be started"
            );
        }
        if (!started.compareAndSet(false, true)) {
            throw new IllegalStateException(
                    "resolver reporter cannot be started again"
            );
        }
        if (config.mode() == ResolverReportingMode.ENABLED) {
            schedule(0);
        }
    }

    synchronized ReportingResult reportOnce() throws Exception {
        requireEnabledAndUsable();
        reportingTelemetry.recordAttempt();
        try {
            if (lease == null) {
                lease = establishSession();
                reportingTelemetry.recordSessionEstablished();
                return ReportingResult.SESSION_ESTABLISHED;
            }

            if (pendingReport == null) {
                pendingReport = captureReport(lease, nextSequence);
            }
            sendReport(pendingReport);
            pendingReport = null;
            reportingTelemetry.recordReportAccepted();
            if (nextSequence == Long.MAX_VALUE) {
                fenced.set(true);
                reportingTelemetry.recordFenced();
            } else {
                nextSequence++;
            }
            return ReportingResult.REPORT_ACCEPTED;
        } catch (FencedSessionException fencedSession) {
            fenced.set(true);
            reportingTelemetry.recordFenced();
            throw fencedSession;
        } catch (Exception failure) {
            reportingTelemetry.recordFailure(lease != null);
            throw failure;
        }
    }

    UUID bootId() {
        return bootId;
    }

    synchronized ResolverSessionLease currentLease() {
        return lease;
    }

    synchronized ResolverRuntimeReport pendingReport() {
        return pendingReport;
    }

    boolean isFenced() {
        return fenced.get();
    }

    ResolverReportingTelemetry.Snapshot telemetrySnapshot() {
        return reportingTelemetry.snapshot();
    }

    long retryDelayMillis(int failureCount) {
        if (failureCount <= 0) {
            throw new IllegalArgumentException(
                    "failureCount must be positive"
            );
        }
        long base = config.initialBackoffMillis();
        for (int index = 1;
                index < failureCount && base < config.maxBackoffMillis();
                index++) {
            base = Math.min(
                    config.maxBackoffMillis(),
                    base > config.maxBackoffMillis() / 2L
                            ? config.maxBackoffMillis()
                            : base * 2L
            );
        }
        double random = Math.max(
                0.0,
                Math.min(1.0, jitterSource.getAsDouble())
        );
        return Math.min(
                config.maxBackoffMillis(),
                Math.max(1L, Math.round(base * (0.8 + random * 0.4)))
        );
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            scheduler.shutdownNow();
        }
    }

    private ResolverSessionLease establishSession() throws Exception {
        ResolverSessionStart start = new ResolverSessionStart(
                bootId,
                config.applicationVersion()
        );
        HttpResponse<byte[]> response = sendJson(
                config.sessionUri(),
                "POST",
                ResolverFleetJsonCodec.writeSessionStart(start)
        );
        if (response.statusCode() == 409) {
            throw new FencedSessionException(
                    "resolver session was rejected by the control plane"
            );
        }
        if (response.statusCode() != 200 && response.statusCode() != 201) {
            throw new IOException(
                    "resolver session endpoint returned HTTP "
                            + response.statusCode()
            );
        }
        validateJsonContentType(response);
        ResolverSessionLease received = ResolverFleetJsonCodec.readSessionLease(
                response.body()
        );
        if (!bootId.equals(received.bootId())) {
            throw new IOException(
                    "resolver session lease does not match this process boot"
            );
        }
        return received;
    }

    private void sendReport(ResolverRuntimeReport report) throws Exception {
        HttpResponse<byte[]> response = sendJson(
                config.reportUri(),
                "PUT",
                ResolverFleetJsonCodec.writeRuntimeReport(report)
        );
        if (response.statusCode() == 409) {
            throw new FencedSessionException(
                    "resolver report session was fenced by the control plane"
            );
        }
        if (response.statusCode() != 204 || response.body().length != 0) {
            throw new IOException(
                    "resolver report endpoint returned an invalid response"
            );
        }
    }

    private HttpResponse<byte[]> sendJson(
            java.net.URI uri,
            String method,
            byte[] body
    ) throws Exception {
        String token = PolicyTokenFile.read(config.tokenFile());
        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofMillis(config.requestTimeoutMillis()))
                .header("Accept", JSON_CONTENT_TYPE)
                .header("Content-Type", JSON_CONTENT_TYPE)
                .header("Authorization", "Bearer " + token)
                .method(method, HttpRequest.BodyPublishers.ofByteArray(body))
                .build();
        return httpClient.send(
                request,
                new LimitedByteArrayBodyHandler(config.maxResponseBytes())
        );
    }

    private ResolverRuntimeReport captureReport(
            ResolverSessionLease activeLease,
            long sequence
    ) {
        PolicyTelemetry.Snapshot policy = policyTelemetry.snapshot(
                policyStore.snapshotStatus()
        );
        return new ResolverRuntimeReport(
                activeLease.sessionId(),
                bootId,
                activeLease.sessionGeneration(),
                sequence,
                config.applicationVersion(),
                switch (policy.mode()) {
                    case DISABLED -> ResolverPolicyMode.DISABLED;
                    case REQUIRED -> ResolverPolicyMode.REQUIRED;
                },
                policy.snapshotLoaded(),
                policy.revision(),
                policy.ruleCount(),
                policy.ready(),
                switch (policy.syncState()) {
                    case DISABLED -> ResolverPolicySyncState.DISABLED;
                    case AWAITING_INITIAL_SNAPSHOT ->
                            ResolverPolicySyncState.AWAITING_INITIAL_SNAPSHOT;
                    case HEALTHY -> ResolverPolicySyncState.HEALTHY;
                    case DEGRADED -> ResolverPolicySyncState.DEGRADED;
                    case STALE -> ResolverPolicySyncState.STALE;
                }
        );
    }

    private void runScheduledAttempt() {
        if (closed.get() || fenced.get()) {
            return;
        }
        long nextDelay;
        try {
            ReportingResult result = reportOnce();
            consecutiveFailures = 0;
            nextDelay = result == ReportingResult.SESSION_ESTABLISHED
                    ? 0
                    : config.reportIntervalMillis();
        } catch (FencedSessionException fencedSession) {
            System.err.println(
                    "Resolver fleet reporting stopped because its session "
                            + "was fenced"
            );
            return;
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return;
        } catch (Exception failure) {
            if (consecutiveFailures < Integer.MAX_VALUE) {
                consecutiveFailures++;
            }
            nextDelay = retryDelayMillis(consecutiveFailures);
            System.err.println(
                    "Resolver fleet reporting failed ("
                            + failure.getClass().getSimpleName()
                            + "); retrying in "
                            + nextDelay
                            + " ms"
            );
        }
        schedule(nextDelay);
    }

    private void schedule(long delayMillis) {
        if (closed.get() || fenced.get()) {
            return;
        }
        try {
            scheduler.schedule(
                    this::runScheduledAttempt,
                    delayMillis,
                    TimeUnit.MILLISECONDS
            );
        } catch (RejectedExecutionException rejected) {
            if (!closed.get()) {
                throw rejected;
            }
        }
    }

    private void requireEnabledAndUsable() {
        if (config.mode() != ResolverReportingMode.ENABLED) {
            throw new IllegalStateException("resolver reporting is disabled");
        }
        if (closed.get()) {
            throw new IllegalStateException("resolver reporter is closed");
        }
        if (fenced.get()) {
            throw new IllegalStateException("resolver reporter is fenced");
        }
    }

    private void validateJsonContentType(HttpResponse<byte[]> response)
            throws IOException {
        List<String> values = response.headers().allValues("Content-Type");
        if (values.size() != 1) {
            throw new IOException(
                    "resolver session response must have one Content-Type"
            );
        }
        String mediaType = values.get(0)
                .split(";", 2)[0]
                .trim()
                .toLowerCase(Locale.ROOT);
        if (!JSON_CONTENT_TYPE.equals(mediaType)) {
            throw new IOException(
                    "resolver session response must be application/json"
            );
        }
    }

    private static HttpClient createHttpClient(
            ResolverReportingConfig config
    ) {
        if (config == null) {
            throw new IllegalArgumentException(
                    "resolver reporting config must not be null"
            );
        }
        return HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(
                        config.connectTimeoutMillis()
                ))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    private static ResolverReportingTelemetry createTelemetry(
            ResolverReportingConfig config
    ) {
        if (config == null) {
            throw new IllegalArgumentException(
                    "resolver reporting config must not be null"
            );
        }
        return new ResolverReportingTelemetry(config.mode());
    }

    private static ScheduledExecutorService createScheduler() {
        return Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "resolver-fleet-reporter");
            thread.setDaemon(true);
            return thread;
        });
    }

    enum ReportingResult {
        SESSION_ESTABLISHED,
        REPORT_ACCEPTED
    }

    static final class FencedSessionException extends IOException {
        private FencedSessionException(String message) {
            super(message);
        }
    }
}
