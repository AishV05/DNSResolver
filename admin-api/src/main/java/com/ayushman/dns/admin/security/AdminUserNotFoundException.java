package com.ayushman.dns.admin.security;

public class AdminUserNotFoundException extends RuntimeException {

    public AdminUserNotFoundException(long id) {
        super("admin user " + id + " was not found");
    }
}
