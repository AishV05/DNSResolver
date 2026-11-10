package com.ayushman.dns.resolver;

/**
 * Fixed-cardinality operational events emitted by the resolver core.
 *
 * <p>The core has no metrics-library dependency. Production servers can
 * provide an observer, while embedders and tests use {@link #NOOP}.</p>
 */
public interface ResolverObserver {

    ResolverObserver NOOP = new ResolverObserver() {
    };

    enum CacheKind {
        POSITIVE,
        NEGATIVE
    }

    default void cacheLookup(CacheKind cache, boolean hit) {
    }

    default void cacheEviction(CacheKind cache) {
    }

    default void upstreamResponseRejected() {
    }

    default void nameserverFailover() {
    }

    default void cnameLoopRejected() {
    }
}
