package com.ayushman.dns.admin.policy;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import com.ayushman.dns.policy.DnsPolicyAction;
import com.ayushman.dns.policy.DnsPolicyMatchType;
import com.ayushman.dns.policy.DnsPolicySnapshot;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest(
        properties = "spring.datasource.url=jdbc:h2:mem:dns_policy_snapshot_concurrency_test;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE"
)
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "dns.admin.bootstrap.username=test-bootstrap-admin",
        "dns.admin.bootstrap.token=test-bootstrap-token-at-least-thirty-two-characters"
})
class DnsPolicySnapshotConcurrencyTest {

    private static final int WRITER_COUNT = 6;

    @Autowired
    private DnsPolicyRuleService ruleService;

    @Autowired
    private DnsPolicySnapshotService snapshotService;

    @Test
    void concurrentWritersAdvanceTheGlobalRevisionWithoutLostUpdates()
            throws Exception {
        DnsPolicySnapshot before = snapshotService.currentSnapshot();
        CountDownLatch ready = new CountDownLatch(WRITER_COUNT);
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(WRITER_COUNT);

        try {
            List<Future<DnsPolicyRuleResponse>> writes = new ArrayList<>();
            for (int index = 0; index < WRITER_COUNT; index++) {
                int writer = index;
                writes.add(executor.submit(() -> {
                    ready.countDown();
                    start.await();
                    return ruleService.create(new CreateDnsPolicyRuleRequest(
                            "writer-" + writer + ".example",
                            DnsPolicyMatchType.EXACT,
                            DnsPolicyAction.BLOCK
                    ));
                }));
            }

            ready.await();
            start.countDown();
            for (Future<DnsPolicyRuleResponse> write : writes) {
                assertThat(write.get()).isNotNull();
            }
        } finally {
            executor.shutdownNow();
        }

        DnsPolicySnapshot after = snapshotService.currentSnapshot();
        assertThat(after.revision())
                .isEqualTo(before.revision() + WRITER_COUNT);
        assertThat(after.rules()).hasSize(WRITER_COUNT);
        assertThat(after.rules())
                .extracting(rule -> rule.domainName())
                .containsExactly(
                        "writer-0.example",
                        "writer-1.example",
                        "writer-2.example",
                        "writer-3.example",
                        "writer-4.example",
                        "writer-5.example"
                );
    }
}
