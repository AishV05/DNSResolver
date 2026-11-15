package com.ayushman.dns.admin.fleet;

import java.util.List;
import java.util.Optional;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

interface ResolverRegistrationRepository
        extends JpaRepository<ResolverRegistrationEntity, String> {

    List<ResolverRegistrationEntity> findAllByOrderByResolverIdAsc();

    Optional<ResolverRegistrationEntity> findByIdentityUserId(long identityUserId);

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            select resolver
            from ResolverRegistrationEntity resolver
            where resolver.resolverId = :resolverId
            """)
    Optional<ResolverRegistrationEntity> findLockedByResolverId(
            @Param("resolverId") String resolverId
    );

    @Lock(LockModeType.PESSIMISTIC_READ)
    @Query("""
            select resolver
            from ResolverRegistrationEntity resolver
            order by resolver.resolverId asc
            """)
    List<ResolverRegistrationEntity> findAllLockedByOrderByResolverIdAsc();

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            select resolver
            from ResolverRegistrationEntity resolver
            where resolver.identityUserId = :identityUserId
            """)
    Optional<ResolverRegistrationEntity> findLockedByIdentityUserId(
            @Param("identityUserId") long identityUserId
    );
}
