package com.ayushman.dns.admin.security;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

class AdminIdentityServiceTest {

    @Test
    void refusesToBootstrapAnEmptyIdentityStoreWithoutExternalCredentials() {
        AdminUserRepository userRepository = mock(AdminUserRepository.class);
        AdminApiTokenRepository tokenRepository = mock(AdminApiTokenRepository.class);
        OpaqueTokenGenerator tokenGenerator = mock(OpaqueTokenGenerator.class);
        when(userRepository.count()).thenReturn(0L);

        AdminIdentityService service = new AdminIdentityService(
                userRepository,
                tokenRepository,
                new AdminBootstrapProperties(),
                tokenGenerator
        );

        assertThatThrownBy(service::bootstrapInitialAdministratorIfRequired)
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("DNS_ADMIN_BOOTSTRAP_USERNAME")
                .hasMessageContaining("DNS_ADMIN_BOOTSTRAP_TOKEN");
        verifyNoInteractions(tokenRepository, tokenGenerator);
    }

    @Test
    void hashesTheBootstrapTokenBeforePersistence() {
        AdminUserRepository userRepository = mock(AdminUserRepository.class);
        AdminApiTokenRepository tokenRepository = mock(AdminApiTokenRepository.class);
        OpaqueTokenGenerator tokenGenerator = mock(OpaqueTokenGenerator.class);
        when(userRepository.count()).thenReturn(0L);
        when(userRepository.saveAndFlush(any(AdminUserEntity.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        AdminBootstrapProperties properties = new AdminBootstrapProperties();
        properties.setUsername("bootstrap-admin");
        properties.setToken("bootstrap-token-at-least-thirty-two-characters");

        AdminIdentityService service = new AdminIdentityService(
                userRepository,
                tokenRepository,
                properties,
                tokenGenerator
        );

        service.bootstrapInitialAdministratorIfRequired();

        ArgumentCaptor<AdminApiTokenEntity> tokenCaptor = ArgumentCaptor.forClass(
                AdminApiTokenEntity.class
        );
        verify(tokenRepository).saveAndFlush(tokenCaptor.capture());
        assertThat(tokenCaptor.getValue().getTokenHash())
                .isEqualTo(TokenHasher.sha256(properties.getToken()))
                .isNotEqualTo(properties.getToken());
        assertThat(tokenCaptor.getValue().getUser().getRoles())
                .containsExactly(AdminRole.ADMIN);
    }

    @Test
    void neverRecreatesOrOverwritesAnExistingIdentityStore() {
        AdminUserRepository userRepository = mock(AdminUserRepository.class);
        AdminApiTokenRepository tokenRepository = mock(AdminApiTokenRepository.class);
        OpaqueTokenGenerator tokenGenerator = mock(OpaqueTokenGenerator.class);
        when(userRepository.count()).thenReturn(1L);

        AdminIdentityService service = new AdminIdentityService(
                userRepository,
                tokenRepository,
                new AdminBootstrapProperties(),
                tokenGenerator
        );

        service.bootstrapInitialAdministratorIfRequired();

        verifyNoInteractions(tokenRepository, tokenGenerator);
    }
}
