package com.ayushman.dns.cache;

/** Bounded positive and negative cache settings for one resolver instance. */
public record ResolverCacheConfig(
        int positiveMaxEntries,
        int negativeMaxEntries,
        long positiveMaxTtlSeconds,
        long negativeMaxTtlSeconds
) {

    public static final int DEFAULT_POSITIVE_MAX_ENTRIES = 1_024;
    public static final int DEFAULT_NEGATIVE_MAX_ENTRIES = 1_024;
    public static final long DEFAULT_POSITIVE_MAX_TTL_SECONDS = 86_400;
    public static final long DEFAULT_NEGATIVE_MAX_TTL_SECONDS = 10_800;

    private static final int MAX_ENTRIES_LIMIT = 1_000_000;
    private static final long MAX_TTL_LIMIT_SECONDS = 604_800;

    public ResolverCacheConfig {
        validateRange(positiveMaxEntries, 1, MAX_ENTRIES_LIMIT,
                "positiveMaxEntries");
        validateRange(negativeMaxEntries, 1, MAX_ENTRIES_LIMIT,
                "negativeMaxEntries");
        validateRange(positiveMaxTtlSeconds, 1, MAX_TTL_LIMIT_SECONDS,
                "positiveMaxTtlSeconds");
        validateRange(negativeMaxTtlSeconds, 1, MAX_TTL_LIMIT_SECONDS,
                "negativeMaxTtlSeconds");
    }

    public static ResolverCacheConfig defaults() {
        return new ResolverCacheConfig(
                DEFAULT_POSITIVE_MAX_ENTRIES,
                DEFAULT_NEGATIVE_MAX_ENTRIES,
                DEFAULT_POSITIVE_MAX_TTL_SECONDS,
                DEFAULT_NEGATIVE_MAX_TTL_SECONDS
        );
    }

    private static void validateRange(
            long value,
            long minimum,
            long maximum,
            String field
    ) {
        if (value < minimum || value > maximum) {
            throw new IllegalArgumentException(
                    field + " must be between " + minimum + " and " + maximum
            );
        }
    }
}
