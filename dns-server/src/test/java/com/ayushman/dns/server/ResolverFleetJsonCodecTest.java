package com.ayushman.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

import com.ayushman.dns.fleet.ResolverPolicyMode;
import com.ayushman.dns.fleet.ResolverPolicySyncState;
import com.ayushman.dns.fleet.ResolverRuntimeReport;
import com.ayushman.dns.fleet.ResolverSessionLease;
import com.ayushman.dns.fleet.ResolverSessionStart;
import org.junit.jupiter.api.Test;

class ResolverFleetJsonCodecTest {

    private static final UUID BOOT_ID = UUID.fromString(
            "10000000-0000-0000-0000-000000000001"
    );
    private static final UUID SESSION_ID = UUID.fromString(
            "20000000-0000-0000-0000-000000000002"
    );

    @Test
    void writesStrictSessionAndRuntimeEnvelopes() throws Exception {
        String start = text(ResolverFleetJsonCodec.writeSessionStart(
                new ResolverSessionStart(BOOT_ID, "0.1.0")
        ));
        assertEquals(
                "{\"schemaVersion\":1,\"bootId\":\"" + BOOT_ID
                        + "\",\"applicationVersion\":\"0.1.0\"}",
                start
        );

        ResolverRuntimeReport report = new ResolverRuntimeReport(
                SESSION_ID,
                BOOT_ID,
                2,
                7,
                "0.1.0",
                ResolverPolicyMode.REQUIRED,
                true,
                9,
                3,
                true,
                ResolverPolicySyncState.HEALTHY
        );
        String encoded = text(
                ResolverFleetJsonCodec.writeRuntimeReport(report)
        );
        assertTrue(encoded.contains("\"sequence\":7"));
        assertTrue(encoded.contains("\"policyRevision\":9"));
        assertTrue(encoded.contains("\"policySyncState\":\"HEALTHY\""));
        assertTrue(!encoded.contains("resolverId"));
        assertTrue(!encoded.contains("timestamp"));
    }

    @Test
    void readsAValidLeaseAndRejectsContractDrift() throws Exception {
        String valid = """
                {"schemaVersion":1,"resolverId":"resolver-a",
                 "sessionId":"%s","bootId":"%s","sessionGeneration":4}
                """.formatted(SESSION_ID, BOOT_ID);
        ResolverSessionLease lease = ResolverFleetJsonCodec.readSessionLease(
                valid.getBytes(StandardCharsets.UTF_8)
        );
        assertEquals("resolver-a", lease.resolverId());
        assertEquals(4, lease.sessionGeneration());

        assertThrows(
                IOException.class,
                () -> read(valid.replace(
                        "\"sessionGeneration\":4",
                        "\"sessionGeneration\":4,\"extra\":true"
                ))
        );
        assertThrows(
                IOException.class,
                () -> read(valid.replace(
                        "\"resolverId\":\"resolver-a\"",
                        "\"resolverId\":\"resolver-a\","
                                + "\"resolverId\":\"resolver-b\""
                ))
        );
        assertThrows(IOException.class, () -> read(valid + "{}"));
        assertThrows(
                IOException.class,
                () -> read(valid.replace("\"schemaVersion\":1,", ""))
        );
        assertThrows(
                IOException.class,
                () -> read(valid.replace(SESSION_ID.toString(), "not-a-uuid"))
        );
    }

    private ResolverSessionLease read(String json) throws IOException {
        return ResolverFleetJsonCodec.readSessionLease(
                json.getBytes(StandardCharsets.UTF_8)
        );
    }

    private String text(byte[] bytes) {
        return new String(bytes, StandardCharsets.UTF_8);
    }
}
