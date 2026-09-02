package com.ayushman.dns.admin.security;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

/**
 * Manages admin identities and opaque API tokens for the control plane.
 *
 * <p>Raw tokens are only accepted at bootstrap or returned once at issuance;
 * only a SHA-256 fingerprint is retained in persistence.</p>
 */
@Service
public class AdminIdentityService {

    private static final int MINIMUM_TOKEN_LENGTH = 32;

    private final AdminUserRepository userRepository;
    private final AdminApiTokenRepository tokenRepository;
    private final AdminBootstrapProperties bootstrapProperties;
    private final OpaqueTokenGenerator tokenGenerator;

    AdminIdentityService(
            AdminUserRepository userRepository,
            AdminApiTokenRepository tokenRepository,
            AdminBootstrapProperties bootstrapProperties,
            OpaqueTokenGenerator tokenGenerator
    ) {
        this.userRepository = userRepository;
        this.tokenRepository = tokenRepository;
        this.bootstrapProperties = bootstrapProperties;
        this.tokenGenerator = tokenGenerator;
    }

    /**
     * Creates the initial administrator only on an empty identity store.
     */
    @Transactional(isolation = Isolation.SERIALIZABLE)
    public void bootstrapInitialAdministratorIfRequired() {
        if (userRepository.count() != 0) {
            return;
        }

        if (!bootstrapProperties.isConfigured()) {
            throw new IllegalStateException(
                    "DNS_ADMIN_BOOTSTRAP_USERNAME and DNS_ADMIN_BOOTSTRAP_TOKEN are required when no admin identity exists"
            );
        }

        String username = AdminUsername.normalize(bootstrapProperties.getUsername());
        String rawToken = bootstrapProperties.getToken();
        validateBootstrapToken(rawToken);

        AdminUserEntity administrator = userRepository.saveAndFlush(
                new AdminUserEntity(username, Set.of(AdminRole.ADMIN))
        );
        tokenRepository.saveAndFlush(new AdminApiTokenEntity(
                administrator,
                TokenHasher.sha256(rawToken),
                "bootstrap",
                null
        ));
    }

    @Transactional(readOnly = true)
    List<AdminUserResponse> listUsers() {
        return userRepository.findAllByOrderByUsernameAsc().stream()
                .map(this::toUserResponse)
                .toList();
    }

    @Transactional
    AdminUserResponse createUser(CreateAdminUserRequest request) {
        String username = AdminUsername.normalize(request.username());
        userRepository.findByUsername(username).ifPresent(ignored -> {
            throw new DuplicateAdminUsernameException(username);
        });

        AdminUserEntity user = userRepository.saveAndFlush(
                new AdminUserEntity(username, Set.of(request.role()))
        );
        return toUserResponse(user);
    }

    @Transactional(readOnly = true)
    List<AdminApiTokenResponse> listTokens(long userId) {
        findUser(userId);
        Instant now = Instant.now();
        return tokenRepository.findAllByUserIdOrderByCreatedAtDesc(userId).stream()
                .map(token -> toTokenResponse(token, now))
                .toList();
    }

    @Transactional
    IssuedAdminApiTokenResponse issueToken(
            long userId,
            IssueAdminApiTokenRequest request
    ) {
        AdminUserEntity user = findUser(userId);
        String tokenLabel = normalizeTokenLabel(request.tokenLabel());
        Instant expiresAt = request.expiresAt();
        if (expiresAt != null && !expiresAt.isAfter(Instant.now())) {
            throw new IllegalArgumentException("token expiration must be in the future");
        }

        String rawToken = tokenGenerator.generate();
        AdminApiTokenEntity token = tokenRepository.saveAndFlush(
                new AdminApiTokenEntity(
                        user,
                        TokenHasher.sha256(rawToken),
                        tokenLabel,
                        expiresAt
                )
        );

        return new IssuedAdminApiTokenResponse(
                token.getId(),
                user.getId(),
                user.getUsername(),
                token.getTokenLabel(),
                rawToken,
                token.getCreatedAt(),
                token.getExpiresAt()
        );
    }

    @Transactional
    void revokeToken(long tokenId) {
        AdminApiTokenEntity token = tokenRepository.findById(tokenId)
                .orElseThrow(() -> new AdminApiTokenNotFoundException(tokenId));
        token.revokeAt(Instant.now());
    }

    /**
     * Resolves a valid token and records its last use. Invalid, expired,
     * revoked, and disabled tokens intentionally all resolve to empty.
     */
    @Transactional
    Optional<AdminAuthenticatedPrincipal> authenticate(String rawToken) {
        if (rawToken == null
                || rawToken.length() < MINIMUM_TOKEN_LENGTH
                || rawToken.length() > 512
                || rawToken.chars().anyMatch(Character::isWhitespace)) {
            return Optional.empty();
        }

        Instant now = Instant.now();
        return tokenRepository.findForAuthenticationByTokenHash(
                        TokenHasher.sha256(rawToken)
                )
                .filter(token -> token.isUsableAt(now))
                .map(token -> {
                    tokenRepository.recordUse(token.getId(), now);
                    AdminUserEntity user = token.getUser();
                    return new AdminAuthenticatedPrincipal(
                            user.getId(),
                            user.getUsername(),
                            user.getRoles()
                    );
                });
    }

    private AdminUserEntity findUser(long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new AdminUserNotFoundException(id));
    }

    private void validateBootstrapToken(String rawToken) {
        if (rawToken.length() < MINIMUM_TOKEN_LENGTH
                || rawToken.chars().anyMatch(Character::isWhitespace)) {
            throw new IllegalArgumentException(
                    "DNS_ADMIN_BOOTSTRAP_TOKEN must be at least 32 non-whitespace characters"
            );
        }
    }

    private String normalizeTokenLabel(String tokenLabel) {
        String normalized = tokenLabel == null ? "" : tokenLabel.trim();
        if (normalized.isEmpty()) {
            throw new IllegalArgumentException("token label must not be blank");
        }
        return normalized;
    }

    private AdminUserResponse toUserResponse(AdminUserEntity user) {
        return new AdminUserResponse(
                user.getId(),
                user.getUsername(),
                user.isEnabled(),
                user.getRoles().stream().sorted().toList(),
                user.getCreatedAt(),
                user.getUpdatedAt(),
                user.getVersion()
        );
    }

    private AdminApiTokenResponse toTokenResponse(
            AdminApiTokenEntity token,
            Instant now
    ) {
        AdminUserEntity user = token.getUser();
        return new AdminApiTokenResponse(
                token.getId(),
                user.getId(),
                user.getUsername(),
                token.getTokenLabel(),
                token.getCreatedAt(),
                token.getExpiresAt(),
                token.getRevokedAt(),
                token.getLastUsedAt(),
                token.isUsableAt(now)
        );
    }
}
