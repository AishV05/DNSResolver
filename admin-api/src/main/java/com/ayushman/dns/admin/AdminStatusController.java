package com.ayushman.dns.admin;

import java.util.List;

import com.ayushman.dns.admin.policy.DnsPolicySnapshotService;
import com.ayushman.dns.admin.policy.DnsPolicySnapshotService.DnsPolicyPublicationStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Read-only management endpoints for control-plane and publication state.
 */
@RestController
@RequestMapping("/api/v1/admin")
public class AdminStatusController {

    private final AdminApiProperties properties;
    private final DnsPolicySnapshotService policySnapshotService;

    public AdminStatusController(
            AdminApiProperties properties,
            DnsPolicySnapshotService policySnapshotService
    ) {
        this.properties = properties;
        this.policySnapshotService = policySnapshotService;
    }

    @GetMapping("/status")
    public AdminStatusResponse status() {
        DnsPolicyPublicationStatus publication =
                policySnapshotService.currentPublicationStatus();
        return new AdminStatusResponse(
                "dns-admin-api",
                "UP",
                "v1",
                properties.getRootServers().size(),
                publication.persistedRuleCount(),
                publication.enabledRuleCount(),
                publication.revision(),
                "SNAPSHOT_AVAILABLE",
                "DATA_PLANE_UNOBSERVED"
        );
    }

    @GetMapping("/resolver/configuration")
    public ResolverConfigurationResponse resolverConfiguration() {
        return new ResolverConfigurationResponse(
                "recursive",
                properties.getRootServers()
        );
    }

    public record AdminStatusResponse(
            String service,
            String status,
            String apiVersion,
            int configuredRootServers,
            long persistedPolicyRules,
            long enabledPolicyRules,
            long publishedPolicyRevision,
            String policyDistribution,
            String policyEnforcement
    ) {
    }

    public record ResolverConfigurationResponse(
            String mode,
            List<String> rootServers
    ) {
    }
}
