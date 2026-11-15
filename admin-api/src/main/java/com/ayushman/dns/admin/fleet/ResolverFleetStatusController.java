package com.ayushman.dns.admin.fleet;

import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Read-only management view of resolver freshness and policy convergence. */
@RestController
@RequestMapping("/api/v1/admin/fleet")
public class ResolverFleetStatusController {

    private final ResolverFleetStatusService service;

    ResolverFleetStatusController(ResolverFleetStatusService service) {
        this.service = service;
    }

    @GetMapping
    ResponseEntity<ResolverFleetStatusResponse> status() {
        return ResponseEntity.ok()
                .cacheControl(CacheControl.noStore())
                .body(service.currentStatus());
    }
}
