package com.ayushman.dns.server;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.time.Instant;
import java.util.List;

import com.ayushman.dns.policy.DnsPolicyAction;
import com.ayushman.dns.policy.DnsPolicyMatchType;
import com.ayushman.dns.policy.DnsPolicyRule;
import com.ayushman.dns.policy.DnsPolicySnapshot;
import com.ayushman.dns.protocol.DnsQuestion;
import org.junit.jupiter.api.Test;

class PolicySnapshotStoreTest {

    @Test
    void distinguishesDisabledFromARequiredEmptyRevisionZero() {
        PolicySnapshotStore disabled = new PolicySnapshotStore(
                PolicySyncMode.DISABLED
        );
        PolicySnapshotStore required = new PolicySnapshotStore(
                PolicySyncMode.REQUIRED
        );

        assertTrue(disabled.isReady());
        assertFalse(required.isReady());
        assertEquals(false, required.snapshotStatus().snapshotLoaded());
        assertEquals(0, required.snapshotStatus().revision());
        assertEquals(
                PolicySnapshotStore.EvaluationResult.ALLOW,
                disabled.evaluate(question("anything.example"))
        );
        assertEquals(
                PolicySnapshotStore.EvaluationResult.UNAVAILABLE,
                required.evaluate(question("anything.example"))
        );

        assertEquals(
                PolicySnapshotStore.ActivationResult.ACTIVATED,
                required.activate(snapshot(0, List.of()))
        );
        assertTrue(required.isReady());
        assertEquals(0, required.currentSnapshot().orElseThrow().revision());
        PolicySnapshotStore.SnapshotStatus status =
                required.snapshotStatus();
        assertTrue(status.snapshotLoaded());
        assertEquals(0, status.revision());
        assertEquals(0, status.ruleCount());
        assertEquals(
                PolicySnapshotStore.EvaluationResult.ALLOW,
                required.evaluate(question("anything.example"))
        );
    }

    @Test
    void rejectsRollbackAndSameRevisionMutationWithoutLosingTheLastGoodState() {
        PolicySnapshotStore store = new PolicySnapshotStore(
                PolicySyncMode.REQUIRED
        );
        DnsPolicySnapshot revisionFive = snapshot(
                5,
                List.of(rule("blocked.example"))
        );
        store.activate(revisionFive);

        assertEquals(
                PolicySnapshotStore.ActivationResult.UNCHANGED,
                store.activate(revisionFive)
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> store.activate(snapshot(4, List.of()))
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> store.activate(snapshot(
                        5,
                        List.of(rule("different.example"))
                ))
        );

        assertEquals(revisionFive, store.currentSnapshot().orElseThrow());
        assertEquals(
                PolicySnapshotStore.EvaluationResult.BLOCK,
                store.evaluate(question("blocked.example"))
        );
        assertEquals(
                PolicySnapshotStore.EvaluationResult.ALLOW,
                store.evaluate(question("different.example"))
        );
    }

    @Test
    void atomicallyMovesOnlyToANewerCompleteSnapshot() {
        PolicySnapshotStore store = new PolicySnapshotStore(
                PolicySyncMode.REQUIRED
        );
        store.activate(snapshot(1, List.of(rule("one.example"))));

        DnsPolicySnapshot revisionTwo = snapshot(
                2,
                List.of(rule("one.example"), rule("two.example"))
        );
        assertEquals(
                PolicySnapshotStore.ActivationResult.ACTIVATED,
                store.activate(revisionTwo)
        );
        assertEquals(revisionTwo, store.currentSnapshot().orElseThrow());
        assertEquals(
                PolicySnapshotStore.EvaluationResult.BLOCK,
                store.evaluate(question("two.example"))
        );
    }

    private DnsPolicySnapshot snapshot(
            long revision,
            List<DnsPolicyRule> rules
    ) {
        return new DnsPolicySnapshot(
                revision,
                Instant.parse("2026-10-04T00:00:00Z").plusSeconds(revision),
                rules
        );
    }

    private DnsPolicyRule rule(String domain) {
        return new DnsPolicyRule(
                domain,
                DnsPolicyMatchType.EXACT,
                DnsPolicyAction.BLOCK
        );
    }

    private DnsQuestion question(String domain) {
        return new DnsQuestion(domain, 1, 1);
    }
}
