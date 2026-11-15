package com.ayushman.dns.admin.metrics;

import com.ayushman.dns.admin.fleet.ResolverFleetStatusResponse;
import com.ayushman.dns.admin.fleet.ResolverFleetStatusService;
import com.ayushman.dns.admin.fleet.ResolverSessionRetentionService;
import com.ayushman.dns.admin.fleet.ResolverSessionRetentionSnapshot;
import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/** Authenticated, fixed-cardinality Prometheus view of fleet convergence. */
@RestController
public class ResolverFleetPrometheusController {

    static final MediaType PROMETHEUS_TEXT_FORMAT = MediaType.parseMediaType(
            "text/plain; version=0.0.4; charset=utf-8"
    );

    private final ResolverFleetStatusService service;
    private final ResolverSessionRetentionService retentionService;

    ResolverFleetPrometheusController(
            ResolverFleetStatusService service,
            ResolverSessionRetentionService retentionService
    ) {
        this.service = service;
        this.retentionService = retentionService;
    }

    @GetMapping(
            path = "/api/v1/internal/fleet-metrics",
            produces = "text/plain; version=0.0.4; charset=utf-8"
    )
    ResponseEntity<String> metrics() {
        ResolverFleetStatusResponse status = service.currentStatus();
        ResolverSessionRetentionSnapshot retention =
                retentionService.currentSnapshot();
        return ResponseEntity.ok()
                .contentType(PROMETHEUS_TEXT_FORMAT)
                .cacheControl(CacheControl.noStore())
                .body(ResolverFleetPrometheusFormatter.format(status, retention));
    }
}
