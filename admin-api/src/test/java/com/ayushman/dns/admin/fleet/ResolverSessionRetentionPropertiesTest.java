package com.ayushman.dns.admin.fleet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class ResolverSessionRetentionPropertiesTest {

    @Test
    void acceptsDocumentedDefaultsAndBoundaries() {
        ResolverSessionRetentionProperties defaults = properties(
                2_592_000_000L,
                3_600_000L,
                500,
                10
        );
        ResolverSessionRetentionProperties minimum = properties(
                86_400_000L,
                60_000L,
                1,
                1
        );
        ResolverSessionRetentionProperties maximum = properties(
                315_360_000_000L,
                86_400_000L,
                5_000,
                100
        );

        assertThat(defaults.enabled()).isTrue();
        assertThat(minimum.cleanupBatchSize()).isEqualTo(1);
        assertThat(maximum.cleanupMaxBatchesPerRun()).isEqualTo(100);
    }

    @Test
    void rejectsUnsafeRetentionAndCleanupBounds() {
        assertThatThrownBy(() -> properties(
                86_399_999L, 60_000L, 1, 1
        )).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> properties(
                315_360_000_001L, 60_000L, 1, 1
        )).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> properties(
                86_400_000L, 59_999L, 1, 1
        )).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> properties(
                86_400_000L, 86_400_000L, 1, 1
        )).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> properties(
                172_800_000L, 60_000L, 0, 1
        )).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> properties(
                172_800_000L, 60_000L, 5_001, 1
        )).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> properties(
                172_800_000L, 60_000L, 1, 0
        )).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> properties(
                172_800_000L, 60_000L, 1, 101
        )).isInstanceOf(IllegalArgumentException.class);
    }

    private ResolverSessionRetentionProperties properties(
            long retention,
            long interval,
            int batchSize,
            int maximumBatches
    ) {
        return new ResolverSessionRetentionProperties(
                true,
                retention,
                interval,
                batchSize,
                maximumBatches
        );
    }
}

