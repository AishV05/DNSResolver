package com.ayushman.dns.fleet;

import java.util.Objects;
import java.util.UUID;
import java.util.regex.Pattern;

final class ResolverRuntimeContracts {

    static final int CURRENT_SCHEMA_VERSION = 1;

    private static final UUID NIL_UUID = new UUID(0, 0);
    private static final Pattern RESOLVER_ID = Pattern.compile(
            "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    );
    private static final Pattern APPLICATION_VERSION = Pattern.compile(
            "[A-Za-z0-9][A-Za-z0-9._+\\-]{0,63}"
    );

    private ResolverRuntimeContracts() {
    }

    static void requireCurrentSchema(int schemaVersion) {
        if (schemaVersion != CURRENT_SCHEMA_VERSION) {
            throw new IllegalArgumentException(
                    "unsupported resolver runtime schema version: "
                            + schemaVersion
            );
        }
    }

    static UUID requireNonNilUuid(UUID value, String fieldName) {
        UUID present = Objects.requireNonNull(
                value,
                fieldName + " must not be null"
        );
        if (NIL_UUID.equals(present)) {
            throw new IllegalArgumentException(
                    fieldName + " must not be the nil UUID"
            );
        }
        return present;
    }

    static String requireResolverId(String value) {
        Objects.requireNonNull(value, "resolverId must not be null");
        if (!RESOLVER_ID.matcher(value).matches()) {
            throw new IllegalArgumentException(
                    "resolverId must be a canonical lowercase DNS label"
            );
        }
        return value;
    }

    static String requireApplicationVersion(String value) {
        Objects.requireNonNull(
                value,
                "applicationVersion must not be null"
        );
        if (!APPLICATION_VERSION.matcher(value).matches()) {
            throw new IllegalArgumentException(
                    "applicationVersion contains unsupported characters"
            );
        }
        return value;
    }
}
