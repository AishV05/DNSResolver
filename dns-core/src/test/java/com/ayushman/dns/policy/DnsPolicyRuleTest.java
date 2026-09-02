package com.ayushman.dns.policy;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class DnsPolicyRuleTest {

    @Test
    void canonicalizesCaseAndTrailingRootLabel() {
        DnsPolicyRule rule = new DnsPolicyRule(
                "Example.COM.",
                DnsPolicyMatchType.DOMAIN_AND_SUBDOMAINS,
                DnsPolicyAction.BLOCK
        );

        assertEquals("example.com", rule.domainName());
    }

    @Test
    void convertsInternationalizedNamesToAscii() {
        DnsPolicyRule rule = new DnsPolicyRule(
                "bücher.example",
                DnsPolicyMatchType.EXACT,
                DnsPolicyAction.BLOCK
        );

        assertEquals("xn--bcher-kva.example", rule.domainName());
    }

    @Test
    void preservesUnderscoreServiceLabels() {
        DnsPolicyRule rule = new DnsPolicyRule(
                "_dmarc.example.com",
                DnsPolicyMatchType.EXACT,
                DnsPolicyAction.BLOCK
        );

        assertEquals("_dmarc.example.com", rule.domainName());
    }

    @Test
    void rejectsMalformedDomainNames() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new DnsPolicyRule(
                        "invalid..example",
                        DnsPolicyMatchType.EXACT,
                        DnsPolicyAction.BLOCK
                )
        );
    }
}
