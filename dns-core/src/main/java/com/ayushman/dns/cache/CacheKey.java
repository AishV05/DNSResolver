package com.ayushman.dns.cache;

import com.ayushman.dns.protocol.DnsQuestion;

public record CacheKey(
        CanonicalDnsName name,
        int type,
        int qclass
) {

    public static CacheKey from(
            DnsQuestion question
    ) {
        return new CacheKey(
                CanonicalDnsName.from(question.name()),
                question.type(),
                question.qclass()
        );
    }
}
