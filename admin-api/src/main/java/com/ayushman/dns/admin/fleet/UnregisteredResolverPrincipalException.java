package com.ayushman.dns.admin.fleet;

public class UnregisteredResolverPrincipalException extends RuntimeException {

    UnregisteredResolverPrincipalException() {
        super("authenticated resolver is not registered");
    }
}
