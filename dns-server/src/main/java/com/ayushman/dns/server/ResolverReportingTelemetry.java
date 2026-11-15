package com.ayushman.dns.server;

import java.time.Clock;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.atomic.LongAdder;

/** Fixed-cardinality state and counters for resolver fleet reporting. */
final class ResolverReportingTelemetry {

    private final ResolverReportingMode mode;
    private final Clock clock;
    private final LongAdder attempts = new LongAdder();
    private final LongAdder sessionsEstablished = new LongAdder();
    private final LongAdder reportsAccepted = new LongAdder();
    private final LongAdder failures = new LongAdder();
    private final AtomicReference<Observation> observation;

    ResolverReportingTelemetry(ResolverReportingMode mode) {
        this(mode, Clock.systemUTC());
    }

    ResolverReportingTelemetry(ResolverReportingMode mode, Clock clock) {
        if (mode == null || clock == null) {
            throw new IllegalArgumentException(
                    "resolver reporting telemetry dependencies must not be null"
            );
        }
        this.mode = mode;
        this.clock = clock;
        this.observation = new AtomicReference<>(new Observation(
                mode == ResolverReportingMode.DISABLED
                        ? State.DISABLED
                        : State.AWAITING_SESSION,
                0,
                0,
                0
        ));
    }

    void recordAttempt() {
        attempts.increment();
        long now = clock.instant().getEpochSecond();
        observation.updateAndGet(current -> new Observation(
                current.state(),
                now,
                current.lastSuccessEpochSeconds(),
                current.consecutiveFailures()
        ));
    }

    void recordSessionEstablished() {
        sessionsEstablished.increment();
        recordSuccess(State.ACTIVE);
    }

    void recordReportAccepted() {
        reportsAccepted.increment();
        recordSuccess(State.ACTIVE);
    }

    void recordFailure(boolean sessionEstablished) {
        failures.increment();
        observation.updateAndGet(current -> new Observation(
                sessionEstablished ? State.DEGRADED : State.AWAITING_SESSION,
                current.lastAttemptEpochSeconds(),
                current.lastSuccessEpochSeconds(),
                current.consecutiveFailures() == Integer.MAX_VALUE
                        ? Integer.MAX_VALUE
                        : current.consecutiveFailures() + 1
        ));
    }

    void recordFenced() {
        observation.updateAndGet(current -> new Observation(
                State.FENCED,
                current.lastAttemptEpochSeconds(),
                current.lastSuccessEpochSeconds(),
                current.consecutiveFailures()
        ));
    }

    Snapshot snapshot() {
        Observation current = observation.get();
        return new Snapshot(
                mode,
                current.state(),
                attempts.sum(),
                sessionsEstablished.sum(),
                reportsAccepted.sum(),
                failures.sum(),
                current.lastAttemptEpochSeconds(),
                current.lastSuccessEpochSeconds(),
                current.consecutiveFailures()
        );
    }

    private void recordSuccess(State state) {
        long now = clock.instant().getEpochSecond();
        observation.updateAndGet(current -> new Observation(
                state,
                current.lastAttemptEpochSeconds(),
                now,
                0
        ));
    }

    enum State {
        DISABLED,
        AWAITING_SESSION,
        ACTIVE,
        DEGRADED,
        FENCED
    }

    record Snapshot(
            ResolverReportingMode mode,
            State state,
            long attempts,
            long sessionsEstablished,
            long reportsAccepted,
            long failures,
            long lastAttemptEpochSeconds,
            long lastSuccessEpochSeconds,
            int consecutiveFailures
    ) {
        static Snapshot disabled() {
            return new Snapshot(
                    ResolverReportingMode.DISABLED,
                    State.DISABLED,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0
            );
        }
    }

    private record Observation(
            State state,
            long lastAttemptEpochSeconds,
            long lastSuccessEpochSeconds,
            int consecutiveFailures
    ) {
    }
}
