package com.ayushman.dns.admin.policy;

import java.util.List;

import com.ayushman.dns.policy.DnsPolicyRule;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class DnsPolicyRuleService {

    private final DnsPolicyRuleRepository repository;

    DnsPolicyRuleService(DnsPolicyRuleRepository repository) {
        this.repository = repository;
    }

    @Transactional(readOnly = true)
    List<DnsPolicyRuleResponse> list() {
        return repository.findAllByOrderByDomainNameAscMatchTypeAsc().stream()
                .map(this::toResponse)
                .toList();
    }

    @Transactional(readOnly = true)
    DnsPolicyRuleResponse get(long id) {
        return toResponse(findById(id));
    }

    @Transactional
    DnsPolicyRuleResponse create(CreateDnsPolicyRuleRequest request) {
        DnsPolicyRule rule = new DnsPolicyRule(
                request.domainName(),
                request.matchType(),
                request.action()
        );

        repository.findByDomainNameAndMatchType(
                rule.domainName(),
                rule.matchType()
                )
                .ifPresent(ignored -> {
                    throw duplicate(rule);
                });

        DnsPolicyRuleEntity entity = new DnsPolicyRuleEntity(
                rule.domainName(),
                rule.matchType(),
                rule.action(),
                true
        );

        return toResponse(repository.saveAndFlush(entity));
    }

    @Transactional
    DnsPolicyRuleResponse update(
            long id,
            UpdateDnsPolicyRuleRequest request
    ) {
        DnsPolicyRuleEntity entity = findById(id);
        DnsPolicyRule rule = new DnsPolicyRule(
                request.domainName(),
                request.matchType(),
                request.action()
        );

        repository.findByDomainNameAndMatchType(
                rule.domainName(),
                rule.matchType()
                )
                .filter(other -> !other.getId().equals(id))
                .ifPresent(ignored -> {
                    throw duplicate(rule);
                });

        entity.update(
                rule.domainName(),
                rule.matchType(),
                rule.action(),
                request.enabled()
        );

        return toResponse(repository.saveAndFlush(entity));
    }

    @Transactional
    void delete(long id) {
        repository.delete(findById(id));
    }

    @Transactional(readOnly = true)
    public long persistedRuleCount() {
        return repository.count();
    }

    @Transactional(readOnly = true)
    public long enabledRuleCount() {
        return repository.countByEnabledTrue();
    }

    private DnsPolicyRuleEntity findById(long id) {
        return repository.findById(id)
                .orElseThrow(() -> new DnsPolicyRuleNotFoundException(id));
    }

    private DuplicateDnsPolicyRuleException duplicate(DnsPolicyRule rule) {
        return new DuplicateDnsPolicyRuleException(
                rule.domainName(),
                rule.matchType().name()
        );
    }

    private DnsPolicyRuleResponse toResponse(DnsPolicyRuleEntity entity) {
        return new DnsPolicyRuleResponse(
                entity.getId(),
                entity.getDomainName(),
                entity.getMatchType(),
                entity.getAction(),
                entity.isEnabled(),
                entity.getCreatedAt(),
                entity.getUpdatedAt(),
                entity.getVersion()
        );
    }
}
