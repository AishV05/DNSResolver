package com.ayushman.dns.admin.policy;

import java.util.Optional;

import jakarta.persistence.LockModeType;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

interface DnsPolicySnapshotStateRepository
        extends JpaRepository<DnsPolicySnapshotStateEntity, Integer> {

    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("""
            select state
            from DnsPolicySnapshotStateEntity state
            where state.singletonId = :singletonId
            """)
    Optional<DnsPolicySnapshotStateEntity> findLockedById(
            @Param("singletonId") int singletonId
    );
}
