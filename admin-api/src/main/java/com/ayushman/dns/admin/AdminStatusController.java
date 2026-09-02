package com.ayushman.dns.admin;

import java.util.List;

import com.ayushman.dns.admin.policy.DnsPolicyRuleService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Read-only management endpoints. Mutating resolver policy is intentionally
 * deferred until durable storage and authentication are available.
 */
@RestController
@RequestMapping("/api/v1/admin")
public class AdminStatusController {

    private final AdminApiProperties properties;
    private final DnsPolicyRuleService policyRuleService;

    public AdminStatusController(
            AdminApiProperties properties,
            DnsPolicyRuleService policyRuleService
    ) {
        this.properties = properties;
        this.policyRuleService = policyRuleService;
    }

    @GetMapping("/status")
    public AdminStatusResponse status() {
        return new AdminStatusResponse(
                "dns-admin-api",
                "UP",
                "v1",
                properties.getRootServers().size(),
                policyRuleService.persistedRuleCount(),
                policyRuleService.enabledRuleCount(),
                "PERSISTED_NOT_APPLIED"
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
            String policyEnforcement
    ) {
    }

    public record ResolverConfigurationResponse(
            String mode,
            List<String> rootServers
    ) {
    }
}
