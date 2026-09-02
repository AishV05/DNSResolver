package com.ayushman.dns.admin.security;

import java.io.IOException;
import java.util.Enumeration;
import java.util.List;
import java.util.Optional;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Authenticates only opaque Bearer tokens. It does not log headers or raw
 * tokens, and all unusable-token cases intentionally share one response.
 */
class OpaqueBearerTokenAuthenticationFilter extends OncePerRequestFilter {

    private final AdminIdentityService identityService;

    OpaqueBearerTokenAuthenticationFilter(AdminIdentityService identityService) {
        this.identityService = identityService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.equals("/actuator/health")
                || path.startsWith("/actuator/health/");
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        Enumeration<String> headers = request.getHeaders(HttpHeaders.AUTHORIZATION);
        if (!headers.hasMoreElements()) {
            filterChain.doFilter(request, response);
            return;
        }

        String authorization = headers.nextElement();
        if (headers.hasMoreElements()) {
            unauthorized(response);
            return;
        }

        String rawToken = extractBearerToken(authorization);
        if (rawToken == null) {
            unauthorized(response);
            return;
        }

        Optional<AdminAuthenticatedPrincipal> principal = identityService.authenticate(
                rawToken
        );
        if (principal.isEmpty()) {
            unauthorized(response);
            return;
        }

        List<SimpleGrantedAuthority> authorities = principal.get().roles().stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role.name()))
                .toList();
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(new UsernamePasswordAuthenticationToken(
                principal.get(),
                null,
                authorities
        ));
        SecurityContextHolder.setContext(context);
        filterChain.doFilter(request, response);
    }

    private String extractBearerToken(String authorization) {
        if (authorization == null
                || authorization.length() <= 7
                || !authorization.regionMatches(true, 0, "Bearer", 0, 6)
                || authorization.charAt(6) != ' ') {
            return null;
        }

        return authorization.substring(7);
    }

    private void unauthorized(HttpServletResponse response) {
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    }
}
