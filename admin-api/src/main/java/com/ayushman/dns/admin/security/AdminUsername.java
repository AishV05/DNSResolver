package com.ayushman.dns.admin.security;

import java.util.Locale;
import java.util.regex.Pattern;

final class AdminUsername {

    private static final Pattern VALID_USERNAME = Pattern.compile(
            "[a-z0-9][a-z0-9._-]{2,63}"
    );

    private AdminUsername() {
    }

    static String normalize(String username) {
        if (username == null) {
            throw new IllegalArgumentException("username must not be blank");
        }

        String normalized = username.trim().toLowerCase(Locale.ROOT);
        if (!VALID_USERNAME.matcher(normalized).matches()) {
            throw new IllegalArgumentException(
                    "username must be 3-64 lowercase ASCII characters using letters, digits, '.', '_' or '-'"
            );
        }

        return normalized;
    }
}
