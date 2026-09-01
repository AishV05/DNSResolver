package com.ayushman.dns.cache;

import com.ayushman.dns.protocol.DnsQuestion;

public record CacheKey(
        String name,
        int type,
        int qclass
) {

    public static CacheKey from(
            DnsQuestion question
    ) {
        return new CacheKey(
                question.name().toLowerCase(),
                question.type(),
                question.qclass()
        );
    }
}