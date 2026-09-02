package com.ayushman.dns.admin.security;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

interface AdminUserRepository extends JpaRepository<AdminUserEntity, Long> {

    Optional<AdminUserEntity> findByUsername(String username);

    List<AdminUserEntity> findAllByOrderByUsernameAsc();
}
