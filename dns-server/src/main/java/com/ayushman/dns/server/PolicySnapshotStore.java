package com.ayushman.dns.server;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import com.ayushman.dns.policy.DnsPolicyDecision;
import com.ayushman.dns.policy.DnsPolicyEvaluator;
import com.ayushman.dns.policy.DnsPolicySnapshot;
import com.ayushman.dns.protocol.DnsQuestion;

/**
 * Atomically exposes one complete validated snapshot and its precompiled
 * evaluator to query threads. A null reference means no required snapshot has
 * been loaded yet; revision zero remains a valid loaded snapshot.
 */
public final class PolicySnapshotStore {

    private final PolicySyncMode mode;
    private final AtomicReference<ActivePolicy> current =
            new AtomicReference<>();

    public PolicySnapshotStore(PolicySyncMode mode) {
        if (mode == null) {
            throw new IllegalArgumentException("policy mode must not be null");
        }
        this.mode = mode;
    }

    public PolicySyncMode mode() {
        return mode;
    }

    public boolean isReady() {
        return mode == PolicySyncMode.DISABLED || current.get() != null;
    }

    public Optional<DnsPolicySnapshot> currentSnapshot() {
        return Optional.ofNullable(current.get())
                .map(ActivePolicy::snapshot);
    }

    SnapshotStatus snapshotStatus() {
        ActivePolicy active = current.get();
        if (active == null) {
            return new SnapshotStatus(
                    mode,
                    isReady(),
                    false,
                    0,
                    0,
                    null
            );
        }
        DnsPolicySnapshot snapshot = active.snapshot();
        return new SnapshotStatus(
                mode,
                true,
                true,
                snapshot.revision(),
                snapshot.rules().size(),
                snapshot.publishedAt()
        );
    }

    EvaluationResult evaluate(DnsQuestion question) {
        if (question == null) {
            throw new IllegalArgumentException(
                    "DNS policy question must not be null"
            );
        }
        if (mode == PolicySyncMode.DISABLED) {
            return EvaluationResult.ALLOW;
        }

        ActivePolicy active = current.get();
        if (active == null) {
            return EvaluationResult.UNAVAILABLE;
        }
        return active.evaluator().evaluate(question)
                == DnsPolicyDecision.BLOCK
                ? EvaluationResult.BLOCK
                : EvaluationResult.ALLOW;
    }

    ActivationResult activate(DnsPolicySnapshot candidate) {
        if (candidate == null) {
            throw new IllegalArgumentException(
                    "policy snapshot must not be null"
            );
        }
        if (mode != PolicySyncMode.REQUIRED) {
            throw new IllegalStateException(
                    "cannot activate a snapshot while policy sync is disabled"
            );
        }

        ActivePolicy candidatePolicy = null;

        while (true) {
            ActivePolicy existing = current.get();
            if (existing != null) {
                if (candidate.revision() < existing.snapshot().revision()) {
                    throw new IllegalArgumentException(
                            "policy snapshot revision moved backwards"
                    );
                }
                if (candidate.revision()
                        == existing.snapshot().revision()) {
                    if (!candidate.equals(existing.snapshot())) {
                        throw new IllegalArgumentException(
                                "policy snapshot changed without a new revision"
                        );
                    }
                    return ActivationResult.UNCHANGED;
                }
            }

            if (candidatePolicy == null) {
                candidatePolicy = new ActivePolicy(
                        candidate,
                        new DnsPolicyEvaluator(candidate)
                );
            }
            if (current.compareAndSet(existing, candidatePolicy)) {
                return ActivationResult.ACTIVATED;
            }
        }
    }

    enum ActivationResult {
        ACTIVATED,
        UNCHANGED
    }

    enum EvaluationResult {
        UNAVAILABLE,
        ALLOW,
        BLOCK
    }

    record SnapshotStatus(
            PolicySyncMode mode,
            boolean ready,
            boolean snapshotLoaded,
            long revision,
            int ruleCount,
            java.time.Instant publishedAt
    ) {
    }

    private record ActivePolicy(
            DnsPolicySnapshot snapshot,
            DnsPolicyEvaluator evaluator
    ) {
    }
}
