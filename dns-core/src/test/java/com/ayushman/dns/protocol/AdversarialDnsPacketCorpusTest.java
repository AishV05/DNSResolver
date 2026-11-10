package com.ayushman.dns.protocol;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import java.time.Duration;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

class AdversarialDnsPacketCorpusTest {

    @Test
    void coversEveryWeek18aMalformedPacketCategory() {
        Set<AdversarialDnsPacketCorpus.Category> categories = EnumSet.noneOf(
                AdversarialDnsPacketCorpus.Category.class
        );
        AdversarialDnsPacketCorpus.all().forEach(fixture -> categories.add(fixture.category()));

        assertEquals(EnumSet.allOf(AdversarialDnsPacketCorpus.Category.class), categories);
    }

    @Test
    void fixtureIdsAreUnique() {
        List<AdversarialDnsPacketCorpus.Fixture> fixtures = AdversarialDnsPacketCorpus.all();
        Set<String> ids = new HashSet<>();

        fixtures.forEach(fixture -> ids.add(fixture.id()));

        assertEquals(fixtures.size(), ids.size());
    }

    @Test
    void fixtureBytesAreDefensiveCopies() {
        byte[] source = {1, 2, 3};
        AdversarialDnsPacketCorpus.Fixture fixture = new AdversarialDnsPacketCorpus.Fixture(
                "defensive-copy-check",
                AdversarialDnsPacketCorpus.Category.TRUNCATED_HEADER,
                AdversarialDnsPacketCorpus.ExpectedDisposition.REJECT_AS_FORMAT_ERROR,
                AdversarialDnsPacketCorpus.ParserBaseline.ASSERT_REJECTS_NOW,
                "Verifies that callers cannot alter stored bytes.",
                source
        );

        source[0] = 9;
        byte[] returned = fixture.wireBytes();
        returned[1] = 9;

        assertEquals(1, fixture.wireBytes()[0]);
        assertEquals(2, fixture.wireBytes()[1]);
    }

    @Test
    void everyFixtureHasTheWeek18FormatErrorDisposition() {
        AdversarialDnsPacketCorpus.all().forEach(fixture -> assertEquals(
                AdversarialDnsPacketCorpus.ExpectedDisposition.REJECT_AS_FORMAT_ERROR,
                fixture.expectedDisposition(),
                fixture.id()
        ));
    }

    @Test
    void catalogCannotBeModified() {
        assertThrows(
                UnsupportedOperationException.class,
                () -> AdversarialDnsPacketCorpus.all().clear()
        );
    }

    @Test
    void everyFixtureIsEnabledForBoundedParserRegression() {
        AdversarialDnsPacketCorpus.all().forEach(fixture -> assertEquals(
                AdversarialDnsPacketCorpus.ParserBaseline.ASSERT_REJECTS_NOW,
                fixture.parserBaseline(),
                fixture.id()
        ));
    }

    @Test
    void everyCorpusPacketIsRejectedPromptlyAsAFormatError() {
        AdversarialDnsPacketCorpus.all().forEach(fixture -> assertTimeoutPreemptively(
                Duration.ofSeconds(1),
                () -> assertThrows(
                        DnsFormatException.class,
                        () -> DnsPacketParser.parse(fixture.wireBytes()),
                        fixture.id()
                ),
                fixture.id()
        ));
    }
}
