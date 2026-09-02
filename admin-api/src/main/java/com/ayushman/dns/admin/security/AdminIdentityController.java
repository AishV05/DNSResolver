package com.ayushman.dns.admin.security;

import java.util.List;

import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/admin")
class AdminIdentityController {

    private final AdminIdentityService identityService;

    AdminIdentityController(AdminIdentityService identityService) {
        this.identityService = identityService;
    }

    @GetMapping("/users")
    List<AdminUserResponse> listUsers() {
        return identityService.listUsers();
    }

    @PostMapping("/users")
    ResponseEntity<AdminUserResponse> createUser(
            @Valid @RequestBody CreateAdminUserRequest request
    ) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(identityService.createUser(request));
    }

    @GetMapping("/users/{id}/tokens")
    List<AdminApiTokenResponse> listTokens(@PathVariable("id") long userId) {
        return identityService.listTokens(userId);
    }

    @PostMapping("/users/{id}/tokens")
    ResponseEntity<IssuedAdminApiTokenResponse> issueToken(
            @PathVariable("id") long userId,
            @Valid @RequestBody IssueAdminApiTokenRequest request
    ) {
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(identityService.issueToken(userId, request));
    }

    @DeleteMapping("/tokens/{id}")
    ResponseEntity<Void> revokeToken(@PathVariable("id") long tokenId) {
        identityService.revokeToken(tokenId);
        return ResponseEntity.noContent().build();
    }
}
