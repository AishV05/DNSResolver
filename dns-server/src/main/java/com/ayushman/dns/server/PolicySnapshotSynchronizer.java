package com.ayushman.dns.server;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.DoubleSupplier;

import com.ayushman.dns.policy.DnsPolicySnapshot;

/**
 * Polls the authenticated control-plane endpoint outside the query path and
 * swaps only complete validated snapshots into the data plane.
 */
public final class PolicySnapshotSynchronizer implements AutoCloseable {

    private static final String ACCEPTED_CONTENT_TYPE = "application/json";

    private final PolicySyncConfig config;
    private final PolicySnapshotStore store;
    private final PolicyTelemetry telemetry;
    private final HttpClient httpClient;
    private final ScheduledExecutorService scheduler;
    private final DoubleSupplier jitterSource;
    private final AtomicReference<String> currentEtag =
            new AtomicReference<>();
    private final AtomicBoolean started = new AtomicBoolean();
    private final AtomicBoolean closed = new AtomicBoolean();

    private int consecutiveFailures;

    public PolicySnapshotSynchronizer(
            PolicySyncConfig config,
            PolicySnapshotStore store
    ) {
        this(config, store, PolicyTelemetry.fromConfig(config));
    }

    PolicySnapshotSynchronizer(
            PolicySyncConfig config,
            PolicySnapshotStore store,
            PolicyTelemetry telemetry
    ) {
        this(
                config,
                store,
                telemetry,
                createHttpClient(config),
                createScheduler(),
                Math::random
        );
    }

    PolicySnapshotSynchronizer(
            PolicySyncConfig config,
            PolicySnapshotStore store,
            HttpClient httpClient,
            ScheduledExecutorService scheduler,
            DoubleSupplier jitterSource
    ) {
        this(
                config,
                store,
                PolicyTelemetry.fromConfig(config),
                httpClient,
                scheduler,
                jitterSource
        );
    }

    PolicySnapshotSynchronizer(
            PolicySyncConfig config,
            PolicySnapshotStore store,
            PolicyTelemetry telemetry,
            HttpClient httpClient,
            ScheduledExecutorService scheduler,
            DoubleSupplier jitterSource
    ) {
        if (config == null
                || store == null
                || telemetry == null
                || httpClient == null
                || scheduler == null
                || jitterSource == null) {
            throw new IllegalArgumentException(
                    "policy synchronizer dependencies must not be null"
            );
        }
        if (config.mode() != store.mode()) {
            throw new IllegalArgumentException(
                    "policy configuration and store modes must match"
            );
        }
        if (config.mode() != telemetry.mode()) {
            throw new IllegalArgumentException(
                    "policy configuration and telemetry modes must match"
            );
        }
        this.config = config;
        this.store = store;
        this.telemetry = telemetry;
        this.httpClient = httpClient;
        this.scheduler = scheduler;
        this.jitterSource = jitterSource;
    }

    public void start() {
        if (closed.get()) {
            throw new IllegalStateException(
                    "closed policy synchronizer cannot be started"
            );
        }
        if (!started.compareAndSet(false, true)) {
            throw new IllegalStateException(
                    "policy synchronizer cannot be started again"
            );
        }
        if (config.mode() == PolicySyncMode.REQUIRED) {
            schedule(0);
        }
    }

    SyncResult synchronizeOnce() throws Exception {
        if (config.mode() != PolicySyncMode.REQUIRED) {
            throw new IllegalStateException(
                    "policy synchronization is disabled"
            );
        }

        telemetry.recordSyncAttempt();
        try {
            SyncResult result = fetchAndActivate();
            recordSyncSuccess(result);
            return result;
        } catch (Exception failure) {
            telemetry.recordSyncFailure();
            throw failure;
        }
    }

    private SyncResult fetchAndActivate() throws Exception {

        String token = PolicyTokenFile.read(config.tokenFile());
        String requestedEtag = currentEtag.get();
        HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(
                        config.snapshotUri()
                )
                .timeout(Duration.ofMillis(config.requestTimeoutMillis()))
                .header("Accept", ACCEPTED_CONTENT_TYPE)
                .header("Authorization", "Bearer " + token)
                .GET();
        if (requestedEtag != null) {
            requestBuilder.header("If-None-Match", requestedEtag);
        }

        HttpResponse<byte[]> response = httpClient.send(
                requestBuilder.build(),
                new LimitedByteArrayBodyHandler(config.maxResponseBytes())
        );

        if (response.statusCode() == 304) {
            validateNotModified(response, requestedEtag);
            return SyncResult.NOT_MODIFIED;
        }
        if (response.statusCode() != 200) {
            throw new IOException(
                    "policy snapshot endpoint returned HTTP "
                            + response.statusCode()
            );
        }

        validateJsonContentType(response);
        DnsPolicySnapshot candidate = PolicySnapshotJsonParser.parse(
                response.body(),
                config.maxRules()
        );
        String responseEtag = requiredStrongEtag(response);
        String expectedEtag = etagFor(candidate);
        if (!expectedEtag.equals(responseEtag)) {
            throw new IOException(
                    "policy snapshot ETag does not match its revision"
            );
        }

        PolicySnapshotStore.ActivationResult activation =
                store.activate(candidate);
        currentEtag.set(responseEtag);
        return activation == PolicySnapshotStore.ActivationResult.ACTIVATED
                ? SyncResult.ACTIVATED
                : SyncResult.UNCHANGED;
    }

    private void recordSyncSuccess(SyncResult result) {
        switch (result) {
            case ACTIVATED -> telemetry.recordSyncActivated();
            case UNCHANGED -> telemetry.recordSyncUnchanged();
            case NOT_MODIFIED -> telemetry.recordSyncNotModified();
        }
    }

    String currentEtag() {
        return currentEtag.get();
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
        double multiplier = 0.8 + (random * 0.4);
        return Math.min(
                config.maxBackoffMillis(),
                Math.max(1L, Math.round(base * multiplier))
        );
    }

    @Override
    public void close() {
        if (closed.compareAndSet(false, true)) {
            scheduler.shutdownNow();
        }
    }

    private void runScheduledAttempt() {
        if (closed.get()) {
            return;
        }

        long nextDelay;
        try {
            SyncResult result = synchronizeOnce();
            consecutiveFailures = 0;
            nextDelay = config.refreshIntervalMillis();
            if (result == SyncResult.ACTIVATED) {
                DnsPolicySnapshot active = store.currentSnapshot()
                        .orElseThrow();
                System.out.println(
                        "Activated policy snapshot revision "
                                + active.revision()
                                + " with "
                                + active.rules().size()
                                + " rules"
                );
            }
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return;
        } catch (Exception failure) {
            if (consecutiveFailures < Integer.MAX_VALUE) {
                consecutiveFailures++;
            }
            nextDelay = retryDelayMillis(consecutiveFailures);
            System.err.println(
                    "Policy snapshot synchronization failed ("
                            + failure.getClass().getSimpleName()
                            + "); retrying in "
                            + nextDelay
                            + " ms"
            );
        }

        schedule(nextDelay);
    }

    private void schedule(long delayMillis) {
        if (closed.get()) {
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

    private void validateNotModified(
            HttpResponse<byte[]> response,
            String requestedEtag
    ) throws IOException {
        if (requestedEtag == null
                || store.currentSnapshot().isEmpty()
                || response.body().length != 0
                || !requestedEtag.equals(requiredStrongEtag(response))) {
            throw new IOException("invalid policy snapshot 304 response");
        }
    }

    private void validateJsonContentType(HttpResponse<byte[]> response)
            throws IOException {
        List<String> values = response.headers().allValues("Content-Type");
        if (values.size() != 1) {
            throw new IOException(
                    "policy snapshot response must have one Content-Type"
            );
        }
        String mediaType = values.get(0)
                .split(";", 2)[0]
                .trim()
                .toLowerCase(Locale.ROOT);
        if (!ACCEPTED_CONTENT_TYPE.equals(mediaType)) {
            throw new IOException(
                    "policy snapshot response must be application/json"
            );
        }
    }

    private String requiredStrongEtag(HttpResponse<byte[]> response)
            throws IOException {
        List<String> values = response.headers().allValues("ETag");
        if (values.size() != 1) {
            throw new IOException(
                    "policy snapshot response must have one ETag"
            );
        }
        String etag = values.get(0).trim();
        if (etag.startsWith("W/")
                || etag.length() < 2
                || etag.charAt(0) != '"'
                || etag.charAt(etag.length() - 1) != '"') {
            throw new IOException(
                    "policy snapshot response requires a strong ETag"
            );
        }
        return etag;
    }

    private String etagFor(DnsPolicySnapshot snapshot) {
        return "\"policy-v"
                + snapshot.schemaVersion()
                + "-r"
                + snapshot.revision()
                + "\"";
    }

    private static HttpClient createHttpClient(PolicySyncConfig config) {
        if (config == null) {
            throw new IllegalArgumentException(
                    "policy sync config must not be null"
            );
        }
        return HttpClient.newBuilder()
                .connectTimeout(Duration.ofMillis(
                        config.connectTimeoutMillis()
                ))
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    private static ScheduledExecutorService createScheduler() {
        return Executors.newSingleThreadScheduledExecutor(runnable -> {
            Thread thread = new Thread(runnable, "policy-snapshot-sync");
            thread.setDaemon(true);
            return thread;
        });
    }

    enum SyncResult {
        ACTIVATED,
        UNCHANGED,
        NOT_MODIFIED
    }
}
