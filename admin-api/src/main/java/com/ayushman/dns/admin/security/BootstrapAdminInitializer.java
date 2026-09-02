package com.ayushman.dns.admin.security;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.stereotype.Component;

/**
 * Runs after persistence has been initialized and before the application is
 * usable, so a new admin API cannot accidentally start with anonymous access.
 */
@Component
class BootstrapAdminInitializer implements InitializingBean {

    private final AdminIdentityService identityService;

    BootstrapAdminInitializer(AdminIdentityService identityService) {
        this.identityService = identityService;
    }

    @Override
    public void afterPropertiesSet() {
        identityService.bootstrapInitialAdministratorIfRequired();
    }
}
