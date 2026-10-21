package com.ayushman.dns.admin.security;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.WebApplicationType;
import org.springframework.context.ConfigurableApplicationContext;

import com.ayushman.dns.admin.AdminApiApplication;

class AdminConfigTreeTest {

    private static final String BOOTSTRAP_TOKEN =
            "config-tree-bootstrap-token-0123456789abcdef";
    private static final String DATABASE_PASSWORD =
            "config-tree-database-password-0123456789abcdef";

    @TempDir
    Path temporaryDirectory;

    @Test
    void loadsDatabaseAndBootstrapSecretsFromMountedFiles() throws IOException {
        Path configDirectory = Files.createDirectory(
                temporaryDirectory.resolve("config")
        );
        Path secretDirectory = Files.createDirectory(
                temporaryDirectory.resolve("secrets")
        );
        Files.writeString(
                secretDirectory.resolve("spring.datasource.password"),
                DATABASE_PASSWORD + "\n",
                StandardCharsets.UTF_8
        );
        Files.writeString(
                secretDirectory.resolve("dns.admin.bootstrap.token"),
                BOOTSTRAP_TOKEN + "\n",
                StandardCharsets.UTF_8
        );

        String databaseName = "config_tree_"
                + UUID.randomUUID().toString().replace("-", "");
        Files.writeString(
                configDirectory.resolve("application.properties"),
                "spring.config.import=configtree:"
                        + secretDirectory.toAbsolutePath()
                        + "/\n"
                        + "dns.admin.bootstrap.username=config-tree-admin\n"
                        + "spring.datasource.url=jdbc:h2:mem:"
                        + databaseName
                        + ";MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;"
                        + "DEFAULT_NULL_ORDERING=HIGH;DB_CLOSE_DELAY=-1;"
                        + "DB_CLOSE_ON_EXIT=FALSE\n"
                        + "spring.datasource.username=sa\n",
                StandardCharsets.UTF_8
        );

        SpringApplication application = new SpringApplication(
                AdminApiApplication.class
        );
        application.setWebApplicationType(WebApplicationType.SERVLET);

        try (ConfigurableApplicationContext context = application.run(
                "--spring.config.additional-location=file:"
                        + configDirectory.toAbsolutePath()
                        + "/",
                "--spring.main.banner-mode=off",
                "--server.port=0",
                "--logging.level.root=OFF"
        )) {
            AdminIdentityService identityService = context.getBean(
                    AdminIdentityService.class
            );

            assertThat(identityService.authenticate(BOOTSTRAP_TOKEN))
                    .isPresent()
                    .get()
                    .satisfies(principal -> {
                        assertThat(principal.username())
                                .isEqualTo("config-tree-admin");
                        assertThat(principal.roles())
                                .containsExactly(AdminRole.ADMIN);
                    });
        }
    }
}
