package com.ayushman.dns.admin.security;

import java.security.SecureRandom;
import java.util.Base64;

import org.springframework.stereotype.Component;

@Component
class OpaqueTokenGenerator {

    static final int TOKEN_BYTES = 32;

    private final SecureRandom secureRandom = new SecureRandom();

    String generate() {
        byte[] bytes = new byte[TOKEN_BYTES];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
