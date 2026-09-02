package com.ayushman.dns.admin.security;

public class AdminApiTokenNotFoundException extends RuntimeException {

    public AdminApiTokenNotFoundException(long id) {
        super("admin API token " + id + " was not found");
    }
}
