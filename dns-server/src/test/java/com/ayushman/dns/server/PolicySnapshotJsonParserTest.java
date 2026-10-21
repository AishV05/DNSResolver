package com.ayushman.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import com.ayushman.dns.policy.DnsPolicyMatchType;
import org.junit.jupiter.api.Test;

class PolicySnapshotJsonParserTest {

    @Test
    void parsesAndCanonicalizesTheVersionOneContract() throws Exception {
        var snapshot = PolicySnapshotJsonParser.parse(bytes("""
                {
                  "schemaVersion": 1,
                  "revision": 7,
                  "publishedAt": "2026-10-04T00:00:00Z",
                  "rules": [
                    {
                      "domainName": "B.Example.",
                      "matchType": "EXACT",
                      "action": "BLOCK"
                    },
                    {
                      "domainName": "a.example",
                      "matchType": "DOMAIN_AND_SUBDOMAINS",
                      "action": "BLOCK"
                    }
                  ]
                }
                """), 10);

        assertEquals(7, snapshot.revision());
        assertEquals(2, snapshot.rules().size());
        assertEquals("a.example", snapshot.rules().get(0).domainName());
        assertEquals(
                DnsPolicyMatchType.DOMAIN_AND_SUBDOMAINS,
                snapshot.rules().get(0).matchType()
        );
        assertEquals("b.example", snapshot.rules().get(1).domainName());
    }

    @Test
    void rejectsUnknownDuplicateMissingAndTrailingFields() {
        assertInvalid("""
                {"schemaVersion":1,"revision":0,
                 "publishedAt":"2026-10-04T00:00:00Z","rules":[],
                 "unexpected":true}
                """);
        assertInvalid("""
                {"schemaVersion":1,"schemaVersion":1,"revision":0,
                 "publishedAt":"2026-10-04T00:00:00Z","rules":[]}
                """);
        assertInvalid("""
                {"schemaVersion":1,"revision":0,"rules":[]}
                """);
        assertInvalid("""
                {"schemaVersion":1,"revision":0,
                 "publishedAt":"2026-10-04T00:00:00Z","rules":[]} {}
                """);
    }

    @Test
    void rejectsUnsupportedValuesAndRuleLimitOverflow() {
        assertInvalid("""
                {"schemaVersion":2,"revision":0,
                 "publishedAt":"2026-10-04T00:00:00Z","rules":[]}
                """);
        assertInvalid("""
                {"schemaVersion":1,"revision":0,
                 "publishedAt":"not-an-instant","rules":[]}
                """);
        assertInvalid("""
                {"schemaVersion":1,"revision":0,
                 "publishedAt":"2026-10-04T00:00:00Z","rules":[
                   {"domainName":"one.example","matchType":"PREFIX",
                    "action":"BLOCK"}]}
                """);

        assertThrows(
                IOException.class,
                () -> PolicySnapshotJsonParser.parse(bytes("""
                        {"schemaVersion":1,"revision":0,
                         "publishedAt":"2026-10-04T00:00:00Z","rules":[
                           {"domainName":"one.example","matchType":"EXACT",
                            "action":"BLOCK"},
                           {"domainName":"two.example","matchType":"EXACT",
                            "action":"BLOCK"}]}
                        """), 1)
        );
    }

    private void assertInvalid(String json) {
        assertThrows(
                Exception.class,
                () -> PolicySnapshotJsonParser.parse(bytes(json), 10)
        );
    }

    private byte[] bytes(String value) {
        return value.getBytes(StandardCharsets.UTF_8);
    }
}
