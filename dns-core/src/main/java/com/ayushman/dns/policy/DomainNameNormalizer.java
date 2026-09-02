package com.ayushman.dns.policy;

import java.net.IDN;
import java.util.Locale;

/**
 * Canonicalizes DNS policy names without tying the core to a web framework or
 * database. A trailing root label is removed and internationalized names are
 * stored in their ASCII form.
 */
public final class DomainNameNormalizer {

    private static final int MAX_DOMAIN_LENGTH = 253;
    private static final int MAX_LABEL_LENGTH = 63;

    private DomainNameNormalizer() {
    }

    public static String normalize(String domainName) {
        if (domainName == null || domainName.isBlank()) {
            throw new IllegalArgumentException("domain name must not be blank");
        }

        if (!domainName.equals(domainName.trim())) {
            throw new IllegalArgumentException(
                    "domain name must not have leading or trailing whitespace"
            );
        }

        String ascii;
        try {
            ascii = IDN.toASCII(domainName).toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException exception) {
            throw new IllegalArgumentException(
                    "domain name is not valid",
                    exception
            );
        }

        if (ascii.endsWith(".")) {
            ascii = ascii.substring(0, ascii.length() - 1);
        }

        if (ascii.isEmpty() || ascii.length() > MAX_DOMAIN_LENGTH) {
            throw new IllegalArgumentException(
                    "domain name must contain between 1 and 253 characters"
            );
        }

        for (String label : ascii.split("\\.", -1)) {
            validateLabel(label);
        }

        return ascii;
    }

    private static void validateLabel(String label) {
        if (label.isEmpty() || label.length() > MAX_LABEL_LENGTH) {
            throw new IllegalArgumentException(
                    "each domain label must contain between 1 and 63 characters"
            );
        }

        if (!label.matches("[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?")) {
            throw new IllegalArgumentException(
                    "domain labels may contain letters, digits, hyphens, and underscores"
            );
        }
    }
}
