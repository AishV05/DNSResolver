package com.ayushman.dns.resolver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class ResolverDnsNameTest {

    @Test
    void comparesAsciiCaseAndTerminalDotsCanonically() {
        assertEquals(
                ResolverDnsName.from("WWW.Example.COM."),
                ResolverDnsName.from("www.example.com")
        );
    }

    @Test
    void comparesBailiwickAtDnsLabelBoundaries() {
        ResolverDnsName zone = ResolverDnsName.from("example.com");

        assertTrue(ResolverDnsName.from("example.com").isAtOrBelow(zone));
        assertTrue(ResolverDnsName.from("www.example.com").isAtOrBelow(zone));
        assertFalse(ResolverDnsName.from("badexample.com").isAtOrBelow(zone));
        assertFalse(ResolverDnsName.from("example.com.test").isAtOrBelow(zone));
    }

    @Test
    void doesNotTreatAnEscapedDotInsideOneLabelAsAZoneBoundary() {
        ResolverDnsName zone = ResolverDnsName.from("example.com");
        ResolverDnsName oneLabel = ResolverDnsName.from("evil\\.example.com");

        assertEquals(2, oneLabel.labelCount());
        assertFalse(oneLabel.isAtOrBelow(zone));
    }

    @Test
    void rootContainsEveryNameButStrictDescentRequiresAnotherLabel() {
        ResolverDnsName root = ResolverDnsName.from("");

        assertTrue(ResolverDnsName.from("example").isStrictlyBelow(root));
        assertFalse(root.isStrictlyBelow(root));
    }
}
