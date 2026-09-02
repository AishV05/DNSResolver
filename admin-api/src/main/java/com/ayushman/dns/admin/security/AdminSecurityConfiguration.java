package com.ayushman.dns.admin.security;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;

/**
 * Security boundary for the standalone management API.
 *
 * <p>It is intentionally Bearer-header only: no cookies, sessions, form
 * login, HTTP Basic, CORS, or request-cache state are enabled.</p>
 */
@Configuration
class AdminSecurityConfiguration {

    @Bean
    SecurityFilterChain adminSecurityFilterChain(
            HttpSecurity http,
            AdminIdentityService identityService
    ) throws Exception {
        OpaqueBearerTokenAuthenticationFilter bearerTokenFilter =
                new OpaqueBearerTokenAuthenticationFilter(identityService);

        http
                .csrf(AbstractHttpConfigurer::disable)
                .cors(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .requestCache(AbstractHttpConfigurer::disable)
                .sessionManagement(session -> session.sessionCreationPolicy(
                        SessionCreationPolicy.STATELESS
                ))
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint((request, response, exception) -> {
                            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
                            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                        })
                        .accessDeniedHandler((request, response, exception) ->
                                response.setStatus(HttpServletResponse.SC_FORBIDDEN)
                        )
                )
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers(
                                HttpMethod.GET,
                                "/actuator/health",
                                "/actuator/health/**"
                        ).permitAll()
                        .requestMatchers(
                                HttpMethod.GET,
                                "/api/v1/admin/auth/me"
                        ).authenticated()
                        .requestMatchers(
                                HttpMethod.GET,
                                "/api/v1/admin/status",
                                "/api/v1/admin/resolver/configuration",
                                "/api/v1/admin/policies",
                                "/api/v1/admin/policies/**"
                        ).hasAnyRole(
                                AdminRole.VIEWER.name(),
                                AdminRole.POLICY_EDITOR.name(),
                                AdminRole.ADMIN.name()
                        )
                        .requestMatchers(
                                HttpMethod.POST,
                                "/api/v1/admin/policies"
                        ).hasAnyRole(
                                AdminRole.POLICY_EDITOR.name(),
                                AdminRole.ADMIN.name()
                        )
                        .requestMatchers(
                                HttpMethod.PUT,
                                "/api/v1/admin/policies/*"
                        ).hasAnyRole(
                                AdminRole.POLICY_EDITOR.name(),
                                AdminRole.ADMIN.name()
                        )
                        .requestMatchers(
                                HttpMethod.DELETE,
                                "/api/v1/admin/policies/*"
                        ).hasAnyRole(
                                AdminRole.POLICY_EDITOR.name(),
                                AdminRole.ADMIN.name()
                        )
                        .requestMatchers(
                                HttpMethod.GET,
                                "/api/v1/admin/users",
                                "/api/v1/admin/users/*/tokens"
                        ).hasRole(AdminRole.ADMIN.name())
                        .requestMatchers(
                                HttpMethod.POST,
                                "/api/v1/admin/users",
                                "/api/v1/admin/users/*/tokens"
                        ).hasRole(AdminRole.ADMIN.name())
                        .requestMatchers(
                                HttpMethod.DELETE,
                                "/api/v1/admin/tokens/*"
                        ).hasRole(AdminRole.ADMIN.name())
                        .anyRequest().denyAll()
                )
                .addFilterBefore(
                        bearerTokenFilter,
                        AnonymousAuthenticationFilter.class
                );

        return http.build();
    }
}
