package com.ayushman.dns.resolver;

import java.util.LinkedHashSet;
import java.util.Set;

import com.ayushman.dns.policy.DnsResolutionPolicy;
import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsQuestion;
import com.ayushman.dns.protocol.DnsRecord;

/** Shared policy checks for resolver implementations and cached responses. */
final class DnsResolutionPolicyEnforcer {

    private static final int TYPE_CNAME = 5;

    private DnsResolutionPolicyEnforcer() {
    }

    static void requireOriginalQuestionAllowed(
            DnsMessage query,
            DnsResolutionPolicy policy
    ) throws Exception {
        if (query == null || policy == null) {
            throw new IllegalArgumentException(
                    "query and policy must not be null"
            );
        }
        if (query.questions().size() != 1) {
            throw new IllegalArgumentException(
                    "resolver policy requires exactly one DNS question"
            );
        }

        policy.requireAllowed(query.questions().get(0));
    }

    static void requireCnameTargetsAllowed(
            DnsMessage response,
            DnsQuestion originalQuestion,
            DnsResolutionPolicy policy
    ) throws Exception {
        if (response == null || originalQuestion == null || policy == null) {
            throw new IllegalArgumentException(
                    "response, question, and policy must not be null"
            );
        }

        Set<ResolverDnsName> evaluated = new LinkedHashSet<>();
        for (DnsRecord answer : response.answers()) {
            if (answer.type() != TYPE_CNAME
                    || answer.qclass() != originalQuestion.qclass()) {
                continue;
            }

            String target;
            try {
                target = DnsRecordUtil.getDomainName(answer);
            } catch (RuntimeException malformedTarget) {
                throw new UpstreamDnsException(
                        "Malformed CNAME target in resolver response",
                        malformedTarget
                );
            }
            if (target == null) {
                throw new UpstreamDnsException(
                        "Malformed CNAME target in resolver response"
                );
            }

            ResolverDnsName canonicalTarget;
            try {
                canonicalTarget = ResolverDnsName.from(target);
            } catch (RuntimeException malformedTarget) {
                throw new UpstreamDnsException(
                        "Invalid CNAME target in resolver response",
                        malformedTarget
                );
            }

            if (evaluated.add(canonicalTarget)) {
                policy.requireAllowed(new DnsQuestion(
                        target,
                        originalQuestion.type(),
                        originalQuestion.qclass()
                ));
            }
        }
    }
}
