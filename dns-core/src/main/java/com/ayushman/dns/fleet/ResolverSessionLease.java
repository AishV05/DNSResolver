package com.ayushman.dns.fleet;

import java.util.UUID;

/**
 * Server-issued identity and ordering lease for one resolver process boot.
 */
public record ResolverSessionLease(
        int schemaVersion,
        String resolverId,
        UUID sessionId,
        UUID bootId,
        long sessionGeneration
) {

    public static final int CURRENT_SCHEMA_VERSION =
            ResolverRuntimeContracts.CURRENT_SCHEMA_VERSION;

    public ResolverSessionLease {
        ResolverRuntimeContracts.requireCurrentSchema(schemaVersion);
        resolverId = new ResolverInstanceId(resolverId).value();
        sessionId = ResolverRuntimeContracts.requireNonNilUuid(
                sessionId,
                "sessionId"
        );
        bootId = ResolverRuntimeContracts.requireNonNilUuid(bootId, "bootId");
        if (sessionGeneration < 1) {
            throw new IllegalArgumentException(
                    "resolver session generation must be positive"
            );
        }
    }

    public ResolverSessionLease(
            String resolverId,
            UUID sessionId,
            UUID bootId,
            long sessionGeneration
    ) {
        this(
                CURRENT_SCHEMA_VERSION,
                resolverId,
                sessionId,
                bootId,
                sessionGeneration
        );
    }
}
