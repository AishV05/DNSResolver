package com.ayushman.dns.admin.security;

public class DuplicateAdminUsernameException extends RuntimeException {

    public DuplicateAdminUsernameException(String username) {
        super("admin username already exists: " + username);
    }
}
