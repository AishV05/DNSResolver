package com.ayushman.dns.admin.fleet;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** Bounded control-plane settings for resolver report freshness. */
@ConfigurationProperties(prefix = "dns.admin.fleet")
public record ResolverFleetStatusProperties(long reportFreshnessMillis) {

    private static final long MINIMUM_FRESHNESS_MILLIS = 1_000;
    private static final long MAXIMUM_FRESHNESS_MILLIS = 14_400_000;

    public ResolverFleetStatusProperties {
        if (reportFreshnessMillis < MINIMUM_FRESHNESS_MILLIS
                || reportFreshnessMillis > MAXIMUM_FRESHNESS_MILLIS) {
            throw new IllegalArgumentException(
                    "dns.admin.fleet.report-freshness-millis must be between "
                            + MINIMUM_FRESHNESS_MILLIS
                            + " and "
                            + MAXIMUM_FRESHNESS_MILLIS
            );
        }
    }
}
