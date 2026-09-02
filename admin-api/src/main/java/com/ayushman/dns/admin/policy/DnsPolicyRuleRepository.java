package com.ayushman.dns.admin.policy;

import java.util.List;
import java.util.Optional;

import com.ayushman.dns.policy.DnsPolicyMatchType;
import org.springframework.data.jpa.repository.JpaRepository;

interface DnsPolicyRuleRepository
        extends JpaRepository<DnsPolicyRuleEntity, Long> {

    List<DnsPolicyRuleEntity> findAllByOrderByDomainNameAscMatchTypeAsc();

    Optional<DnsPolicyRuleEntity> findByDomainNameAndMatchType(
            String domainName,
            DnsPolicyMatchType matchType
    );

    long countByEnabledTrue();
}
