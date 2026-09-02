package com.ayushman.dns.admin.policy;

final class DuplicateDnsPolicyRuleException extends RuntimeException {

    DuplicateDnsPolicyRuleException(
            String domainName,
            String matchType
    ) {
        super("A DNS policy rule already exists for "
                + domainName + " with match type " + matchType);
    }
}
