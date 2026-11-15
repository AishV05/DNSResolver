package com.ayushman.dns.admin.fleet;

import com.ayushman.dns.admin.security.AdminAuthenticatedPrincipal;
import com.ayushman.dns.fleet.ResolverRuntimeReport;
import com.ayushman.dns.fleet.ResolverSessionLease;
import com.ayushman.dns.fleet.ResolverSessionStart;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/internal/resolver")
public class ResolverFleetInternalController {

    private final ResolverFleetService service;

    ResolverFleetInternalController(ResolverFleetService service) {
        this.service = service;
    }

    @PostMapping("/session")
    ResponseEntity<ResolverSessionLease> startSession(
            @AuthenticationPrincipal AdminAuthenticatedPrincipal principal,
            @Valid @RequestBody ResolverSessionStart request
    ) {
        ResolverSessionStartResult result = service.startSession(
                principal.userId(),
                request
        );
        HttpStatus status = result.created()
                ? HttpStatus.CREATED
                : HttpStatus.OK;
        return ResponseEntity.status(status).body(result.lease());
    }

    @PutMapping("/report")
    ResponseEntity<Void> report(
            @AuthenticationPrincipal AdminAuthenticatedPrincipal principal,
            @Valid @RequestBody ResolverRuntimeReport report
    ) {
        service.acceptReport(principal.userId(), report);
        return ResponseEntity.noContent().build();
    }
}
