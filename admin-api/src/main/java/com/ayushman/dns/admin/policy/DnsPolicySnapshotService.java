package com.ayushman.dns.admin.policy;

import java.time.Instant;

import com.ayushman.dns.policy.DnsPolicyRule;
import com.ayushman.dns.policy.DnsPolicySnapshot;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Publishes a deterministic snapshot from one transactionally consistent
 * view of the global revision and enabled policy rows.
 */
@Service
public class DnsPolicySnapshotService {

    private final DnsPolicySnapshotStateRepository stateRepository;
    private final DnsPolicyRuleRepository ruleRepository;

    DnsPolicySnapshotService(
            DnsPolicySnapshotStateRepository stateRepository,
            DnsPolicyRuleRepository ruleRepository
    ) {
        this.stateRepository = stateRepository;
        this.ruleRepository = ruleRepository;
    }

    @Transactional
    public DnsPolicySnapshot currentSnapshot() {
        DnsPolicySnapshotStateEntity state = lockedState();
        return new DnsPolicySnapshot(
                state.getRevision(),
                state.getPublishedAt(),
                ruleRepository
                        .findAllByEnabledTrueOrderByDomainNameAscMatchTypeAsc()
                        .stream()
                        .map(entity -> new DnsPolicyRule(
                                entity.getDomainName(),
                                entity.getMatchType(),
                                entity.getAction()
                        ))
                        .toList()
        );
    }

    @Transactional
    public DnsPolicyPublicationStatus currentPublicationStatus() {
        DnsPolicySnapshotStateEntity state = lockedState();
        return new DnsPolicyPublicationStatus(
                state.getRevision(),
                state.getPublishedAt(),
                ruleRepository.count(),
                ruleRepository.countByEnabledTrue()
        );
    }

    DnsPolicySnapshotStateEntity lockedState() {
        return stateRepository.findLockedById(
                DnsPolicySnapshotStateEntity.SINGLETON_ID
        ).orElseThrow(() -> new IllegalStateException(
                "DNS policy snapshot state is missing"
        ));
    }

    void publish(DnsPolicySnapshotStateEntity state) {
        state.advance(Instant.now());
    }

    public record DnsPolicyPublicationStatus(
            long revision,
            Instant publishedAt,
            long persistedRuleCount,
            long enabledRuleCount
    ) {
    }
}
