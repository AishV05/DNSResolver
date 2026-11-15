package com.ayushman.dns.admin.fleet;

import java.time.Instant;
import java.util.List;

import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Performs one portable, bounded cleanup transaction. */
@Service
class ResolverSessionPruner {

    private final ResolverSessionRepository repository;

    ResolverSessionPruner(ResolverSessionRepository repository) {
        this.repository = repository;
    }

    @Transactional
    int pruneBatch(Instant cutoff, int batchSize) {
        List<String> candidates = repository.findRetentionCandidateIds(
                cutoff,
                PageRequest.of(0, batchSize)
        );
        if (candidates.isEmpty()) {
            return 0;
        }
        int deleted = repository.deleteRetentionCandidates(candidates, cutoff);
        repository.flush();
        return deleted;
    }

    @Transactional(readOnly = true)
    boolean hasEligibleSessions(Instant cutoff) {
        return repository.countRetentionEligible(cutoff) > 0;
    }
}

