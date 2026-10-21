package com.ayushman.dns.policy;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * Immutable, deterministic policy input for a DNS data-plane instance.
 *
 * <p>The revision identifies the complete rule set, not an individual row.
 * Disabled control-plane records must be excluded before this snapshot is
 * created.</p>
 */
public record DnsPolicySnapshot(
        int schemaVersion,
        long revision,
        Instant publishedAt,
        List<DnsPolicyRule> rules
) {

    public static final int CURRENT_SCHEMA_VERSION = 1;

    private static final Comparator<DnsPolicyRule> RULE_ORDER =
            Comparator.comparing(DnsPolicyRule::domainName)
                    .thenComparing(rule -> rule.matchType().name())
                    .thenComparing(rule -> rule.action().name());

    public DnsPolicySnapshot {
        if (schemaVersion != CURRENT_SCHEMA_VERSION) {
            throw new IllegalArgumentException(
                    "unsupported policy snapshot schema version: "
                            + schemaVersion
            );
        }
        if (revision < 0) {
            throw new IllegalArgumentException(
                    "policy snapshot revision must not be negative"
            );
        }

        publishedAt = Objects.requireNonNull(
                publishedAt,
                "publishedAt must not be null"
        );
        if (rules == null) {
            throw new IllegalArgumentException("rules must not be null");
        }

        List<DnsPolicyRule> orderedRules = new ArrayList<>(rules.size());
        Set<RuleIdentity> identities = new HashSet<>();
        for (DnsPolicyRule rule : rules) {
            DnsPolicyRule presentRule = Objects.requireNonNull(
                    rule,
                    "policy snapshot rules must not contain null"
            );
            RuleIdentity identity = new RuleIdentity(
                    presentRule.domainName(),
                    presentRule.matchType()
            );
            if (!identities.add(identity)) {
                throw new IllegalArgumentException(
                        "duplicate policy rule for "
                                + presentRule.domainName()
                                + " and "
                                + presentRule.matchType()
                );
            }
            orderedRules.add(presentRule);
        }
        orderedRules.sort(RULE_ORDER);
        rules = List.copyOf(orderedRules);
    }

    public DnsPolicySnapshot(
            long revision,
            Instant publishedAt,
            List<DnsPolicyRule> rules
    ) {
        this(CURRENT_SCHEMA_VERSION, revision, publishedAt, rules);
    }

    private record RuleIdentity(
            String domainName,
            DnsPolicyMatchType matchType
    ) {
    }
}
