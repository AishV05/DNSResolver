package com.ayushman.dns.admin.fleet;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.sql.Timestamp;
import java.time.Instant;
import java.util.UUID;

import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

class ResolverBootFenceMigrationTest {

    @Test
    void upgradingFromV5BackfillsEverySessionBeforeAddingTheFence() {
        String databaseName = "resolver_fence_upgrade_"
                + UUID.randomUUID().toString().replace("-", "");
        String url = "jdbc:h2:mem:"
                + databaseName
                + ";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;"
                + "DEFAULT_NULL_ORDERING=HIGH;DB_CLOSE_DELAY=-1;"
                + "DB_CLOSE_ON_EXIT=FALSE";
        DriverManagerDataSource dataSource = new DriverManagerDataSource(
                url,
                "sa",
                ""
        );
        Flyway.configure()
                .dataSource(dataSource)
                .locations("classpath:db/migration")
                .target(MigrationVersion.fromVersion("5"))
                .load()
                .migrate();

        JdbcTemplate jdbc = new JdbcTemplate(dataSource);
        Instant started = Instant.parse("2026-11-01T00:00:00Z");
        jdbc.update(
                "INSERT INTO admin_users (username, enabled, created_at, updated_at, version) VALUES (?, TRUE, ?, ?, 0)",
                "migration-resolver",
                Timestamp.from(started),
                Timestamp.from(started)
        );
        Long userId = jdbc.queryForObject(
                "SELECT id FROM admin_users WHERE username = ?",
                Long.class,
                "migration-resolver"
        );
        jdbc.update(
                "INSERT INTO resolver_instances (resolver_id, identity_user_id, enabled, active_session_id, last_session_generation, created_at, updated_at, version) VALUES (?, ?, TRUE, NULL, 2, ?, ?, 0)",
                "migration-resolver",
                userId,
                Timestamp.from(started),
                Timestamp.from(started)
        );

        String oldSession = UUID.randomUUID().toString();
        String activeSession = UUID.randomUUID().toString();
        String oldBoot = UUID.randomUUID().toString();
        String activeBoot = UUID.randomUUID().toString();
        insertSession(
                jdbc,
                oldSession,
                oldBoot,
                1,
                started,
                started.plusSeconds(60)
        );
        insertSession(
                jdbc,
                activeSession,
                activeBoot,
                2,
                started.plusSeconds(120),
                null
        );
        jdbc.update(
                "UPDATE resolver_instances SET active_session_id = ? WHERE resolver_id = ?",
                activeSession,
                "migration-resolver"
        );

        Flyway.configure()
                .dataSource(dataSource)
                .locations("classpath:db/migration")
                .load()
                .migrate();

        assertThat(jdbc.queryForObject(
                "SELECT COUNT(*) FROM resolver_boot_fences WHERE resolver_id = ?",
                Long.class,
                "migration-resolver"
        )).isEqualTo(2);
        assertThat(jdbc.queryForObject(
                "SELECT first_seen_at FROM resolver_boot_fences WHERE boot_id = ?",
                Timestamp.class,
                oldBoot
        ).toInstant()).isEqualTo(started);
        assertThatThrownBy(() -> jdbc.update(
                "DELETE FROM resolver_boot_fences WHERE boot_id = ?",
                oldBoot
        )).isInstanceOf(DataIntegrityViolationException.class);
        assertThatThrownBy(() -> jdbc.update(
                "INSERT INTO resolver_boot_fences (resolver_id, boot_id, session_generation, first_seen_at) VALUES (?, ?, ?, ?)",
                "migration-resolver",
                oldBoot,
                3,
                Timestamp.from(started)
        )).isInstanceOf(DataIntegrityViolationException.class);
    }

    private void insertSession(
            JdbcTemplate jdbc,
            String sessionId,
            String bootId,
            long generation,
            Instant startedAt,
            Instant supersededAt
    ) {
        jdbc.update(
                "INSERT INTO resolver_sessions (session_id, resolver_id, boot_id, session_generation, application_version, started_at, superseded_at, version) VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
                sessionId,
                "migration-resolver",
                bootId,
                generation,
                "0.1.0",
                Timestamp.from(startedAt),
                supersededAt == null ? null : Timestamp.from(supersededAt)
        );
    }
}
