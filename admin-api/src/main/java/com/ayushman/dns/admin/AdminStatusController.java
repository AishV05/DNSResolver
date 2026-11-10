package com.ayushman.dns.admin;

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

    private final DnsPolicySnapshotService policySnapshotService;

    public AdminStatusController(
            DnsPolicySnapshotService policySnapshotService
    ) {
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
                publication.persistedRuleCount(),
                publication.enabledRuleCount(),
                publication.revision(),
                "SNAPSHOT_AVAILABLE",
                "DATA_PLANE_UNOBSERVED"
        );
    }

    public record AdminStatusResponse(
            String service,
            String status,
            String apiVersion,
            long persistedPolicyRules,
            long enabledPolicyRules,
            long publishedPolicyRevision,
            String policyDistribution,
            String policyEnforcement
    ) {
    }
}
