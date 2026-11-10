package com.ayushman.dns.resolver;

import com.ayushman.dns.policy.DnsResolutionPolicy;
import com.ayushman.dns.protocol.DnsMessage;

/** Resolves a parsed DNS query without imposing a transport or framework. */
@FunctionalInterface
public interface DnsResolver {

    DnsMessage resolve(DnsMessage query) throws Exception;

    /**
     * Resolves with one request-scoped policy view. Existing implementations
     * remain compatible; the default path checks the original question and
     * every returned CNAME target around their legacy resolve method.
     */
    default DnsMessage resolve(
            DnsMessage query,
            DnsResolutionPolicy policy
    ) throws Exception {
        DnsResolutionPolicyEnforcer.requireOriginalQuestionAllowed(
                query,
                policy
        );
        DnsMessage response = resolve(query);
        DnsResolutionPolicyEnforcer.requireCnameTargetsAllowed(
                response,
                query.questions().get(0),
                policy
        );
        return response;
    }
}
