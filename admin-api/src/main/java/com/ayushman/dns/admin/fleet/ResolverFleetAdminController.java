package com.ayushman.dns.admin.fleet;

import java.net.URI;
import java.util.List;

import jakarta.validation.Valid;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

@RestController
@RequestMapping("/api/v1/admin/resolvers")
public class ResolverFleetAdminController {

    private final ResolverFleetService service;

    ResolverFleetAdminController(ResolverFleetService service) {
        this.service = service;
    }

    @GetMapping
    List<ResolverRegistrationResponse> list() {
        return service.listRegistrations();
    }

    @GetMapping("/{resolverId}")
    ResolverRegistrationResponse get(
            @PathVariable("resolverId") String resolverId
    ) {
        return service.getRegistration(resolverId);
    }

    @PostMapping
    ResponseEntity<RegisteredResolverResponse> register(
            @Valid @RequestBody RegisterResolverRequest request
    ) {
        RegisteredResolverResponse response = service.register(request);
        URI location = ServletUriComponentsBuilder.fromCurrentRequest()
                .path("/{resolverId}")
                .buildAndExpand(response.resolver().resolverId())
                .toUri();
        return ResponseEntity.created(location)
                .cacheControl(CacheControl.noStore())
                .body(response);
    }

    @PutMapping("/{resolverId}")
    ResolverRegistrationResponse update(
            @PathVariable("resolverId") String resolverId,
            @Valid @RequestBody UpdateResolverRegistrationRequest request
    ) {
        return service.updateRegistration(resolverId, request);
    }
}
