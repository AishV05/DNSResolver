package com.ayushman.dns.fleet;

import java.util.UUID;

/** Request used by an authenticated resolver to start a reporting session. */
public record ResolverSessionStart(
        int schemaVersion,
        UUID bootId,
        String applicationVersion
) {

    public static final int CURRENT_SCHEMA_VERSION =
            ResolverRuntimeContracts.CURRENT_SCHEMA_VERSION;

    public ResolverSessionStart {
        ResolverRuntimeContracts.requireCurrentSchema(schemaVersion);
        bootId = ResolverRuntimeContracts.requireNonNilUuid(bootId, "bootId");
        applicationVersion = ResolverRuntimeContracts.requireApplicationVersion(
                applicationVersion
        );
    }

    public ResolverSessionStart(UUID bootId, String applicationVersion) {
        this(CURRENT_SCHEMA_VERSION, bootId, applicationVersion);
    }
}
