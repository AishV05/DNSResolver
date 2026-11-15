package com.ayushman.dns.admin;

import com.ayushman.dns.admin.fleet.ResolverFleetStatusResponse;
import com.ayushman.dns.admin.fleet.ResolverFleetStatusService;
import com.ayushman.dns.fleet.ResolverFleetPolicyState;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Read-only management endpoints for control-plane and publication state.
 */
@RestController
@RequestMapping("/api/v1/admin")
public class AdminStatusController {

    private final ResolverFleetStatusService fleetStatusService;

    public AdminStatusController(
            ResolverFleetStatusService fleetStatusService
    ) {
        this.fleetStatusService = fleetStatusService;
    }

    @GetMapping("/status")
    public AdminStatusResponse status() {
        ResolverFleetStatusResponse fleet = fleetStatusService.currentStatus();
        return new AdminStatusResponse(
                "dns-admin-api",
                "UP",
                "v1",
                fleet.persistedPolicyRuleCount(),
                fleet.publishedPolicyRuleCount(),
                fleet.publishedPolicyRevision(),
                "SNAPSHOT_AVAILABLE",
                fleet.policyEnforcement()
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
            ResolverFleetPolicyState policyEnforcement
    ) {
    }
}
