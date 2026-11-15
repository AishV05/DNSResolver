package com.ayushman.dns.admin.fleet;

public class ResolverRegistrationNotFoundException extends RuntimeException {

    ResolverRegistrationNotFoundException(String resolverId) {
        super("resolver registration not found: " + resolverId);
    }
}
