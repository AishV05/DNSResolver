package com.ayushman.dns.admin;

import java.util.List;

import com.ayushman.dns.resolver.RootServers;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Read-only resolver topology exposed by the management API.
 *
 * <p>Set {@code DNS_ADMIN_ROOT_SERVERS} as a comma-separated list to override
 * the default root-server list for this management process.</p>
 */
@ConfigurationProperties(prefix = "dns.admin")
public class AdminApiProperties {

    private List<String> rootServers = RootServers.ROOT_SERVERS;

    public List<String> getRootServers() {
        return List.copyOf(rootServers);
    }

    public void setRootServers(List<String> rootServers) {
        if (rootServers == null || rootServers.isEmpty()) {
            throw new IllegalArgumentException(
                    "dns.admin.root-servers must not be empty"
            );
        }

        if (rootServers.stream().anyMatch(
                server -> server == null || server.isBlank()
        )) {
            throw new IllegalArgumentException(
                    "dns.admin.root-servers must not contain blank values"
            );
        }

        this.rootServers = List.copyOf(rootServers);
    }
}
