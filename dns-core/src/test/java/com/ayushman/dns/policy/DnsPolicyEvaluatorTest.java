package com.ayushman.dns.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.stream.IntStream;

import org.junit.jupiter.api.Test;

import com.ayushman.dns.protocol.DnsQuestion;

class DnsPolicyEvaluatorTest {

    private static final int TYPE_A = 1;
    private static final int TYPE_AAAA = 28;
    private static final int CLASS_IN = 1;
    private static final int CLASS_CH = 3;
    private static final int CLASS_ANY = 255;

    @Test
    void exactRuleMatchesOnlyTheCanonicalApex() {
        DnsPolicyEvaluator evaluator = evaluator(
                rule("Example.COM.", DnsPolicyMatchType.EXACT)
        );

        assertEquals(
                DnsPolicyDecision.BLOCK,
                evaluator.evaluate(question("example.com", TYPE_A, CLASS_IN))
        );
        assertEquals(
                DnsPolicyDecision.BLOCK,
                evaluator.evaluate(question("EXAMPLE.COM.", TYPE_AAAA, CLASS_IN))
        );
        assertEquals(
                DnsPolicyDecision.ALLOW,
                evaluator.evaluate(question("www.example.com", TYPE_A, CLASS_IN))
        );
    }

    @Test
    void domainRuleMatchesApexAndDescendantsAtLabelBoundaries() {
        DnsPolicyEvaluator evaluator = evaluator(rule(
                "example.com",
                DnsPolicyMatchType.DOMAIN_AND_SUBDOMAINS
        ));

        assertEquals(
                DnsPolicyDecision.BLOCK,
                evaluator.evaluate(question("example.com", TYPE_A, CLASS_IN))
        );
        assertEquals(
                DnsPolicyDecision.BLOCK,
                evaluator.evaluate(question("www.example.com", TYPE_A, CLASS_IN))
        );
        assertEquals(
                DnsPolicyDecision.BLOCK,
                evaluator.evaluate(question("a.b.example.com", TYPE_AAAA, CLASS_IN))
        );
        assertEquals(
                DnsPolicyDecision.ALLOW,
                evaluator.evaluate(question("badexample.com", TYPE_A, CLASS_IN))
        );
        assertEquals(
                DnsPolicyDecision.ALLOW,
                evaluator.evaluate(question("example.com.test", TYPE_A, CLASS_IN))
        );
    }

    @Test
    void canonicalizesInternationalizedAndServiceNames() {
        DnsPolicyEvaluator evaluator = evaluator(
                rule("bücher.example", DnsPolicyMatchType.EXACT),
                rule(
                        "_service.example.com",
                        DnsPolicyMatchType.DOMAIN_AND_SUBDOMAINS
                )
        );

        assertEquals(
                DnsPolicyDecision.BLOCK,
                evaluator.evaluate(question(
                        "xn--bcher-kva.example",
                        TYPE_A,
                        CLASS_IN
                ))
        );
        assertEquals(
                DnsPolicyDecision.BLOCK,
                evaluator.evaluate(question(
                        "BÜCHER.EXAMPLE.",
                        TYPE_A,
                        CLASS_IN
                ))
        );
        assertEquals(
                DnsPolicyDecision.BLOCK,
                evaluator.evaluate(question(
                        "node._SERVICE.EXAMPLE.COM.",
                        TYPE_AAAA,
                        CLASS_IN
                ))
        );
    }

    @Test
    void evaluatesEveryQueryTypeAndClassWithoutAClassBypass() {
        DnsPolicyEvaluator evaluator = evaluator(
                rule("example.com", DnsPolicyMatchType.EXACT)
        );

        assertEquals(
                DnsPolicyDecision.BLOCK,
                evaluator.evaluate(question("example.com", 255, CLASS_IN))
        );
        assertEquals(
                DnsPolicyDecision.BLOCK,
                evaluator.evaluate(question("example.com", TYPE_A, CLASS_CH))
        );
        assertEquals(
                DnsPolicyDecision.BLOCK,
                evaluator.evaluate(question("example.com", TYPE_A, CLASS_ANY))
        );
    }

    @Test
    void emptySnapshotAndNamesOutsideThePolicyGrammarDoNotMatch() {
        DnsPolicyEvaluator evaluator = evaluator();

        assertEquals(
                DnsPolicyDecision.ALLOW,
                evaluator.evaluate(question("example.com", TYPE_A, CLASS_IN))
        );
        assertEquals(
                DnsPolicyDecision.ALLOW,
                evaluator.evaluate(question(".", TYPE_A, CLASS_IN))
        );
        assertEquals(
                DnsPolicyDecision.ALLOW,
                evaluator.evaluate(question("invalid..name", TYPE_A, CLASS_IN))
        );
    }

    @Test
    void exposesTheExactImmutableSnapshotUsedForEvaluation() {
        DnsPolicySnapshot snapshot = snapshot(
                rule("example.com", DnsPolicyMatchType.EXACT)
        );
        DnsPolicyEvaluator evaluator = new DnsPolicyEvaluator(snapshot);

        assertSame(snapshot, evaluator.snapshot());
    }

    @Test
    void supportsConcurrentEvaluationWithoutMutableState() {
        DnsPolicyEvaluator evaluator = evaluator(rule(
                "example.com",
                DnsPolicyMatchType.DOMAIN_AND_SUBDOMAINS
        ));
        ConcurrentLinkedQueue<String> failures =
                new ConcurrentLinkedQueue<>();

        IntStream.range(0, 5_000).parallel().forEach(index -> {
            String domain = index % 2 == 0
                    ? "node" + index + ".example.com"
                    : "node" + index + ".example.net";
            DnsPolicyDecision expected = index % 2 == 0
                    ? DnsPolicyDecision.BLOCK
                    : DnsPolicyDecision.ALLOW;
            if (evaluator.evaluate(question(domain, TYPE_A, CLASS_IN))
                    != expected) {
                failures.add(domain);
            }
        });

        assertEquals(List.of(), List.copyOf(failures));
    }

    @Test
    void rejectsNullEvaluatorInputs() {
        assertThrows(
                NullPointerException.class,
                () -> new DnsPolicyEvaluator(null)
        );
        assertThrows(
                NullPointerException.class,
                () -> evaluator().evaluate(null)
        );
    }

    private DnsPolicyEvaluator evaluator(
            DnsPolicyRule... rules
    ) {
        return new DnsPolicyEvaluator(snapshot(rules));
    }

    private DnsPolicySnapshot snapshot(
            DnsPolicyRule... rules
    ) {
        return new DnsPolicySnapshot(
                12,
                Instant.parse("2026-01-01T00:00:00Z"),
                List.of(rules)
        );
    }

    private DnsPolicyRule rule(
            String domainName,
            DnsPolicyMatchType matchType
    ) {
        return new DnsPolicyRule(
                domainName,
                matchType,
                DnsPolicyAction.BLOCK
        );
    }

    private DnsQuestion question(
            String domainName,
            int type,
            int questionClass
    ) {
        return new DnsQuestion(domainName, type, questionClass);
    }
}
