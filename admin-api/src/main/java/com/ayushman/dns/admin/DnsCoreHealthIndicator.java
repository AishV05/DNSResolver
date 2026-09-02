package com.ayushman.dns.admin;

import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.stereotype.Component;

/**
 * Confirms that the management plane has a usable resolver topology.
 * No external DNS request is made by a health probe.
 */
@Component("dnsCore")
public class DnsCoreHealthIndicator implements HealthIndicator {

    private final AdminApiProperties properties;

    public DnsCoreHealthIndicator(AdminApiProperties properties) {
        this.properties = properties;
    }

    @Override
    public Health health() {
        int rootServerCount = properties.getRootServers().size();

        if (rootServerCount == 0) {
            return Health.down()
                    .withDetail("reason", "No root servers configured")
                    .build();
        }

        return Health.up()
                .withDetail("configuredRootServers", rootServerCount)
                .build();
    }
}
