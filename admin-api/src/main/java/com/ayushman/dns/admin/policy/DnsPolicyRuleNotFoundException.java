package com.ayushman.dns.admin.policy;

final class DnsPolicyRuleNotFoundException extends RuntimeException {

    DnsPolicyRuleNotFoundException(long id) {
        super("DNS policy rule " + id + " was not found");
    }
}
