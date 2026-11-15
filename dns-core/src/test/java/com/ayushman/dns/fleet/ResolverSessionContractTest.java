package com.ayushman.dns.fleet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.Test;

class ResolverSessionContractTest {

    private static final UUID BOOT_ID =
            UUID.fromString("ca7a8e37-a50f-4bca-b66a-e44fc8a79898");
    private static final UUID SESSION_ID =
            UUID.fromString("0aefb223-6f13-4c73-8259-b1cbe8ff4a91");
    private static final UUID NIL_UUID = new UUID(0, 0);

    @Test
    void createsSessionStartWithoutAClientSuppliedResolverIdentity() {
        ResolverSessionStart request = new ResolverSessionStart(
                BOOT_ID,
                "0.1.0-SNAPSHOT"
        );

        assertEquals(1, request.schemaVersion());
        assertEquals(BOOT_ID, request.bootId());
        assertEquals("0.1.0-SNAPSHOT", request.applicationVersion());
    }

    @Test
    void acceptsSafeApplicationVersionFormsAndBoundaries() {
        assertEquals(
                "a",
                new ResolverSessionStart(BOOT_ID, "a").applicationVersion()
        );
        String maximumLength = "v" + "1".repeat(63);
        assertEquals(
                maximumLength,
                new ResolverSessionStart(
                        BOOT_ID,
                        maximumLength
                ).applicationVersion()
        );
        assertEquals(
                "1.2.3+build.7",
                new ResolverSessionStart(
                        BOOT_ID,
                        "1.2.3+build.7"
                ).applicationVersion()
        );
    }

    @Test
    void rejectsInvalidSessionStartFields() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new ResolverSessionStart(2, BOOT_ID, "0.1.0")
        );
        assertThrows(
                NullPointerException.class,
                () -> new ResolverSessionStart(null, "0.1.0")
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> new ResolverSessionStart(NIL_UUID, "0.1.0")
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> new ResolverSessionStart(BOOT_ID, "")
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> new ResolverSessionStart(BOOT_ID, "v 1")
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> new ResolverSessionStart(
                        BOOT_ID,
                        "v" + "1".repeat(64)
                )
        );
    }

    @Test
    void createsServerIssuedLeaseBoundToIdentityAndBoot() {
        ResolverSessionLease lease = new ResolverSessionLease(
                "resolver-india-01",
                SESSION_ID,
                BOOT_ID,
                Long.MAX_VALUE
        );

        assertEquals(1, lease.schemaVersion());
        assertEquals("resolver-india-01", lease.resolverId());
        assertEquals(SESSION_ID, lease.sessionId());
        assertEquals(BOOT_ID, lease.bootId());
        assertEquals(Long.MAX_VALUE, lease.sessionGeneration());
    }

    @Test
    void acceptsCanonicalResolverIdBoundaries() {
        assertEquals(
                "a",
                new ResolverInstanceId("a").value()
        );
        String maximumLength = "r" + "1".repeat(62);
        assertEquals(
                maximumLength,
                new ResolverInstanceId(maximumLength).toString()
        );
        assertEquals(
                "resolver--blue",
                new ResolverInstanceId("resolver--blue").value()
        );
    }

    @Test
    void rejectsInvalidResolverIds() {
        assertInvalidResolverId("");
        assertInvalidResolverId("Resolver-01");
        assertInvalidResolverId("-resolver");
        assertInvalidResolverId("resolver-");
        assertInvalidResolverId("resolver_01");
        assertInvalidResolverId("resolver.example");
        assertInvalidResolverId("resolver 01");
        assertInvalidResolverId("résolveur");
        assertInvalidResolverId("r" + "1".repeat(63));
        assertThrows(
                NullPointerException.class,
                () -> new ResolverInstanceId(null)
        );
    }

    @Test
    void rejectsInvalidLeaseFields() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new ResolverSessionLease(
                        0,
                        "resolver-01",
                        SESSION_ID,
                        BOOT_ID,
                        1
                )
        );
        assertThrows(
                NullPointerException.class,
                () -> new ResolverSessionLease(
                        "resolver-01",
                        null,
                        BOOT_ID,
                        1
                )
        );
        assertThrows(
                NullPointerException.class,
                () -> new ResolverSessionLease(
                        "resolver-01",
                        SESSION_ID,
                        null,
                        1
                )
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> new ResolverSessionLease(
                        "resolver-01",
                        NIL_UUID,
                        BOOT_ID,
                        1
                )
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> new ResolverSessionLease(
                        "resolver-01",
                        SESSION_ID,
                        NIL_UUID,
                        1
                )
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> new ResolverSessionLease(
                        "resolver-01",
                        SESSION_ID,
                        BOOT_ID,
                        0
                )
        );
    }

    @Test
    void keepsVersionOneWireRecordShapesExplicit() {
        assertEquals(
                List.of("schemaVersion", "bootId", "applicationVersion"),
                recordComponentNames(ResolverSessionStart.class)
        );
        assertEquals(
                List.of(
                        "schemaVersion",
                        "resolverId",
                        "sessionId",
                        "bootId",
                        "sessionGeneration"
                ),
                recordComponentNames(ResolverSessionLease.class)
        );
        assertEquals(
                List.of(
                        "schemaVersion",
                        "sessionId",
                        "bootId",
                        "sessionGeneration",
                        "sequence",
                        "applicationVersion",
                        "policyMode",
                        "policySnapshotLoaded",
                        "policyRevision",
                        "policyRuleCount",
                        "policyReady",
                        "policySyncState"
                ),
                recordComponentNames(ResolverRuntimeReport.class)
        );
    }

    private void assertInvalidResolverId(String resolverId) {
        assertThrows(
                IllegalArgumentException.class,
                () -> new ResolverInstanceId(resolverId)
        );
    }

    private List<String> recordComponentNames(Class<?> type) {
        return Arrays.stream(type.getRecordComponents())
                .map(component -> component.getName())
                .toList();
    }
}
