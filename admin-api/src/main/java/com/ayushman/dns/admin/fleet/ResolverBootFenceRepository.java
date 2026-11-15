package com.ayushman.dns.admin.fleet;

import org.springframework.data.jpa.repository.JpaRepository;

interface ResolverBootFenceRepository
        extends JpaRepository<ResolverBootFenceEntity, Long> {

    boolean existsByResolverIdAndBootId(String resolverId, String bootId);
}

