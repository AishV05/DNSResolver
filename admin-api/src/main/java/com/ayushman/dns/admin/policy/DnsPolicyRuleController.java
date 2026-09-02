package com.ayushman.dns.admin.policy;

import java.net.URI;
import java.util.List;

import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

/**
 * CRUD API for durable policy-control-plane records. A created rule is not
 * considered live DNS enforcement until a future snapshot consumer applies it.
 */
@RestController
@RequestMapping("/api/v1/admin/policies")
public class DnsPolicyRuleController {

    private final DnsPolicyRuleService service;

    public DnsPolicyRuleController(DnsPolicyRuleService service) {
        this.service = service;
    }

    @GetMapping
    public List<DnsPolicyRuleResponse> list() {
        return service.list();
    }

    @GetMapping("/{id}")
    public DnsPolicyRuleResponse get(@PathVariable("id") long id) {
        return service.get(id);
    }

    @PostMapping
    public ResponseEntity<DnsPolicyRuleResponse> create(
            @Valid @RequestBody CreateDnsPolicyRuleRequest request
    ) {
        DnsPolicyRuleResponse response = service.create(request);
        URI location = ServletUriComponentsBuilder.fromCurrentRequest()
                .path("/{id}")
                .buildAndExpand(response.id())
                .toUri();

        return ResponseEntity.created(location).body(response);
    }

    @PutMapping("/{id}")
    public DnsPolicyRuleResponse update(
            @PathVariable("id") long id,
            @Valid @RequestBody UpdateDnsPolicyRuleRequest request
    ) {
        return service.update(id, request);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable("id") long id) {
        service.delete(id);
        return ResponseEntity.noContent().build();
    }
}
