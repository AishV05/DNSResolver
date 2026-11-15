package com.ayushman.dns.admin.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;

@SpringBootTest(
        webEnvironment = SpringBootTest.WebEnvironment.MOCK,
        properties = "spring.datasource.url=jdbc:h2:mem:fleet_metrics_migration_test;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH;DB_CLOSE_DELAY=-1;DB_CLOSE_ON_EXIT=FALSE"
)
@ActiveProfiles("test")
@TestPropertySource(properties = {
        "dns.admin.bootstrap.username=test-bootstrap-admin",
        "dns.admin.bootstrap.token=test-bootstrap-token-at-least-thirty-two-characters"
})
class FleetMetricsRoleMigrationTest {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void finalRoleConstraintAcceptsMetricsReaderAndRejectsUnknownRoles() {
        Long userId = jdbcTemplate.queryForObject(
                "SELECT id FROM admin_users WHERE username = ?",
                Long.class,
                "test-bootstrap-admin"
        );

        int inserted = jdbcTemplate.update(
                "INSERT INTO admin_user_roles (user_id, role) VALUES (?, ?)",
                userId,
                AdminRole.FLEET_METRICS_READER.name()
        );

        assertThat(inserted).isEqualTo(1);
        assertThatThrownBy(() -> jdbcTemplate.update(
                "INSERT INTO admin_user_roles (user_id, role) VALUES (?, ?)",
                userId,
                "UNRECOGNIZED_ROLE"
        )).isInstanceOf(DataIntegrityViolationException.class);
    }
}
