package com.ayushman.dns.fleet;

/** Stable, canonical identity assigned to one registered resolver. */
public record ResolverInstanceId(String value) {

    public ResolverInstanceId {
        value = ResolverRuntimeContracts.requireResolverId(value);
    }

    @Override
    public String toString() {
        return value;
    }
}
