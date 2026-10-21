package com.ayushman.dns.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;

class DnsPolicySnapshotTest {

    private static final Instant PUBLISHED_AT =
            Instant.parse("2026-01-01T00:00:00Z");

    @Test
    void copiesAndDeterministicallyOrdersRules() {
        List<DnsPolicyRule> source = new ArrayList<>(List.of(
                rule("z.example", DnsPolicyMatchType.EXACT),
                rule("example.com", DnsPolicyMatchType.EXACT),
                rule(
                        "example.com",
                        DnsPolicyMatchType.DOMAIN_AND_SUBDOMAINS
                )
        ));

        DnsPolicySnapshot snapshot = new DnsPolicySnapshot(
                7,
                PUBLISHED_AT,
                source
        );
        source.clear();

        assertEquals(7, snapshot.revision());
        assertEquals(PUBLISHED_AT, snapshot.publishedAt());
        assertEquals(
                List.of(
                        DnsPolicyMatchType.DOMAIN_AND_SUBDOMAINS,
                        DnsPolicyMatchType.EXACT,
                        DnsPolicyMatchType.EXACT
                ),
                snapshot.rules().stream()
                        .map(DnsPolicyRule::matchType)
                        .toList()
        );
        assertEquals(
                List.of("example.com", "example.com", "z.example"),
                snapshot.rules().stream()
                        .map(DnsPolicyRule::domainName)
                        .toList()
        );
        assertThrows(
                UnsupportedOperationException.class,
                () -> snapshot.rules().clear()
        );
    }

    @Test
    void acceptsAnEmptyInitialSnapshot() {
        DnsPolicySnapshot snapshot = new DnsPolicySnapshot(
                0,
                PUBLISHED_AT,
                List.of()
        );

        assertEquals(0, snapshot.revision());
        assertEquals(List.of(), snapshot.rules());
    }

    @Test
    void rejectsUnsupportedSchemaNegativeRevisionAndNullInputs() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new DnsPolicySnapshot(
                        2,
                        0,
                        PUBLISHED_AT,
                        List.of()
                )
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> new DnsPolicySnapshot(-1, PUBLISHED_AT, List.of())
        );
        assertThrows(
                NullPointerException.class,
                () -> new DnsPolicySnapshot(0, null, List.of())
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> new DnsPolicySnapshot(0, PUBLISHED_AT, null)
        );
        assertThrows(
                NullPointerException.class,
                () -> new DnsPolicySnapshot(
                        0,
                        PUBLISHED_AT,
                        Arrays.asList((DnsPolicyRule) null)
                )
        );
    }

    @Test
    void rejectsDuplicateDomainAndMatchType() {
        DnsPolicyRule first = rule("example.com", DnsPolicyMatchType.EXACT);
        DnsPolicyRule duplicate = rule(
                "EXAMPLE.COM.",
                DnsPolicyMatchType.EXACT
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> new DnsPolicySnapshot(
                        1,
                        PUBLISHED_AT,
                        List.of(first, duplicate)
                )
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
}
