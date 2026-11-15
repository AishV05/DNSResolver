package com.ayushman.dns.admin.fleet;

import java.time.Instant;
import java.util.Collection;
import java.util.List;

import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

interface ResolverSessionRepository
        extends JpaRepository<ResolverSessionEntity, String> {

    long countBySupersededAtIsNull();

    long countBySupersededAtIsNotNull();

    @Query("""
            select count(session)
            from ResolverSessionEntity session
            where session.supersededAt < :cutoff
              and not exists (
                  select registration.resolverId
                  from ResolverRegistrationEntity registration
                  where registration.activeSessionId = session.sessionId
              )
            """)
    long countRetentionEligible(@Param("cutoff") Instant cutoff);

    @Query("""
            select session.sessionId
            from ResolverSessionEntity session
            where session.supersededAt < :cutoff
              and not exists (
                  select registration.resolverId
                  from ResolverRegistrationEntity registration
                  where registration.activeSessionId = session.sessionId
              )
            order by session.supersededAt asc, session.sessionId asc
            """)
    List<String> findRetentionCandidateIds(
            @Param("cutoff") Instant cutoff,
            Pageable pageable
    );

    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            delete from ResolverSessionEntity session
            where session.sessionId in :sessionIds
              and session.supersededAt < :cutoff
              and not exists (
                  select registration.resolverId
                  from ResolverRegistrationEntity registration
                  where registration.activeSessionId = session.sessionId
              )
            """)
    int deleteRetentionCandidates(
            @Param("sessionIds") Collection<String> sessionIds,
            @Param("cutoff") Instant cutoff
    );
}
