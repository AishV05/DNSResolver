package com.ayushman.dns.admin.security;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/admin/auth")
class AdminAuthenticationController {

    @GetMapping("/me")
    AuthenticatedAdminResponse me(
            @AuthenticationPrincipal AdminAuthenticatedPrincipal principal
    ) {
        return new AuthenticatedAdminResponse(
                principal.userId(),
                principal.username(),
                principal.roles().stream().sorted().toList()
        );
    }
}
