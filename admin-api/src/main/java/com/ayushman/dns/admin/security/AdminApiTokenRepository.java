package com.ayushman.dns.admin.security;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

interface AdminApiTokenRepository extends JpaRepository<AdminApiTokenEntity, Long> {

    @Query("""
            select distinct token
            from AdminApiTokenEntity token
            join fetch token.user user
            left join fetch user.roles
            where token.tokenHash = :tokenHash
            """)
    Optional<AdminApiTokenEntity> findForAuthenticationByTokenHash(
            @Param("tokenHash") String tokenHash
    );

    List<AdminApiTokenEntity> findAllByUserIdOrderByCreatedAtDesc(long userId);

    /**
     * Update only the audit timestamp, so concurrent revocation cannot be
     * overwritten by a stale managed entity update.
     */
    @Modifying
    @Query("""
            update AdminApiTokenEntity token
            set token.lastUsedAt = :lastUsedAt
            where token.id = :id
              and token.revokedAt is null
            """)
    int recordUse(
            @Param("id") long id,
            @Param("lastUsedAt") Instant lastUsedAt
    );
}
