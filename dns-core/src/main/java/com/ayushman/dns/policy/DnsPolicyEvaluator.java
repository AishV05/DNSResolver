package com.ayushman.dns.policy;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import com.ayushman.dns.protocol.DnsQuestion;

/**
 * Immutable, thread-safe evaluator built from one complete policy snapshot.
 * Evaluation performs no I/O, one exact lookup, and at most one subtree
 * lookup per domain label.
 */
public final class DnsPolicyEvaluator {

    private final DnsPolicySnapshot snapshot;
    private final Set<String> exactBlockedDomains;
    private final Set<String> blockedDomainTrees;

    public DnsPolicyEvaluator(
            DnsPolicySnapshot snapshot
    ) {
        this.snapshot = Objects.requireNonNull(
                snapshot,
                "snapshot must not be null"
        );

        Set<String> exactRules = new HashSet<>();
        Set<String> domainTreeRules = new HashSet<>();
        for (DnsPolicyRule rule : snapshot.rules()) {
            if (rule.action() != DnsPolicyAction.BLOCK) {
                throw new IllegalArgumentException(
                        "unsupported policy action: " + rule.action()
                );
            }

            switch (rule.matchType()) {
                case EXACT -> exactRules.add(rule.domainName());
                case DOMAIN_AND_SUBDOMAINS ->
                        domainTreeRules.add(rule.domainName());
            }
        }

        exactBlockedDomains = Set.copyOf(exactRules);
        blockedDomainTrees = Set.copyOf(domainTreeRules);
    }

    /**
     * Evaluates the owner name independently of query type and class because
     * the policy model is domain-wide. Names outside the policy name grammar
     * do not match a blocking rule.
     */
    public DnsPolicyDecision evaluate(
            DnsQuestion question
    ) {
        Objects.requireNonNull(question, "question must not be null");

        String domainName;
        try {
            domainName = DomainNameNormalizer.normalize(question.name());
        } catch (IllegalArgumentException invalidName) {
            return DnsPolicyDecision.ALLOW;
        }

        if (exactBlockedDomains.contains(domainName)) {
            return DnsPolicyDecision.BLOCK;
        }

        String candidate = domainName;
        while (true) {
            if (blockedDomainTrees.contains(candidate)) {
                return DnsPolicyDecision.BLOCK;
            }

            int labelBoundary = candidate.indexOf('.');
            if (labelBoundary < 0) {
                return DnsPolicyDecision.ALLOW;
            }
            candidate = candidate.substring(labelBoundary + 1);
        }
    }

    public DnsPolicySnapshot snapshot() {
        return snapshot;
    }
}
