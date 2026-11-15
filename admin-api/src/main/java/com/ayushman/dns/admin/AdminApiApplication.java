package com.ayushman.dns.admin;

import java.time.Clock;

import tools.jackson.core.StreamReadFeature;
import org.springframework.context.annotation.Bean;
import org.springframework.boot.jackson.autoconfigure.JsonFactoryBuilderCustomizer;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;

/**
 * Separate HTTP management plane for the DNS platform.
 *
 * <p>It has no dependency on {@code dns-server}; the UDP request path stays
 * isolated from administrative HTTP traffic.</p>
 */
@SpringBootApplication(exclude = UserDetailsServiceAutoConfiguration.class)
@ConfigurationPropertiesScan
public class AdminApiApplication {

    @Bean
    Clock systemClock() {
        return Clock.systemUTC();
    }

    @Bean
    JsonFactoryBuilderCustomizer strictDuplicateJsonKeys() {
        return builder -> builder.enable(
                StreamReadFeature.STRICT_DUPLICATE_DETECTION
        );
    }

    public static void main(String[] args) {
        SpringApplication.run(AdminApiApplication.class, args);
    }
}
