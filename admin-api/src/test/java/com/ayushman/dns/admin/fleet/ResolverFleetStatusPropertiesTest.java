package com.ayushman.dns.admin.fleet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class ResolverFleetStatusPropertiesTest {

    @Test
    void acceptsBoundedFreshnessThresholds() {
        assertThat(new ResolverFleetStatusProperties(1_000)
                .reportFreshnessMillis()).isEqualTo(1_000);
        assertThat(new ResolverFleetStatusProperties(14_400_000)
                .reportFreshnessMillis()).isEqualTo(14_400_000);
    }

    @Test
    void rejectsUnboundedFreshnessThresholds() {
        assertThatThrownBy(() -> new ResolverFleetStatusProperties(999))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() ->
                new ResolverFleetStatusProperties(14_400_001)
        ).isInstanceOf(IllegalArgumentException.class);
    }
}
