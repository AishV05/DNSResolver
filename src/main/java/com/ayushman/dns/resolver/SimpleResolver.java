package com.ayushman.dns.resolver;

import java.util.List;

import com.ayushman.dns.cache.CachedDnsData;
import com.ayushman.dns.cache.DnsCache;
import com.ayushman.dns.protocol.DnsHeader;
import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsQuestion;
import com.ayushman.dns.protocol.DnsRecord;

public class SimpleResolver {

    private final DnsCache cache = new DnsCache();

    public DnsMessage resolve(DnsMessage query) {

        DnsQuestion question = query.questions().get(0);

        CachedDnsData cached = cache.get(question);

        if (cached != null) {

            System.out.println("CACHE HIT: " + question.name());

            long ttl = cache.remainingTtl(question);

        return ResolverResponseFactory.create(
                query,
                cached,
                ttl
        );
        }

        System.out.println("CACHE MISS: " + question.name());

        DnsHeader requestHeader = query.header();

        DnsHeader responseHeader =
                new DnsHeader(
                        requestHeader.id(),
                        0x8180,
                        requestHeader.qdCount(),
                        1,
                        0,
                        0
                );

        byte[] ip = new byte[]{1, 2, 3, 4};

        DnsRecord answer =
                new DnsRecord(
                        question.name(),
                        1,
                        1,
                        300,
                        ip
                );

        DnsMessage response =
                new DnsMessage(
                        responseHeader,
                        query.questions(),
                        List.of(answer),
                        List.of(),
                        List.of()
                );

        cache.put(
                question,
                response,
                answer.ttl()
        );

        return response;
    }
}