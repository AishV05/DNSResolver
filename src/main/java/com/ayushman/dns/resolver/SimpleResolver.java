package com.ayushman.dns.resolver;
import java.util.List;

import com.ayushman.dns.cache.DnsCache;
import com.ayushman.dns.protocol.DnsHeader;
import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsQuestion;
import com.ayushman.dns.protocol.DnsRecord;

public class SimpleResolver{
    private final DnsCache cache = new DnsCache();
    public DnsMessage resolve(DnsMessage query) {

        DnsQuestion question = query.questions().get(0);

        DnsMessage cached = cache.get(question);

        if (cached != null) {

            System.out.println("Cache HIT for " + question.name());

            DnsHeader newHeader = new DnsHeader(
                    query.header().id(),      
                    cached.header().flags(),
                    cached.header().qdCount(),
                    cached.header().anCount(),
                    cached.header().nsCount(),
                    cached.header().arCount()
            );

            return new DnsMessage(
                        newHeader,
                        cached.questions(),
                        cached.answers(),
                        cached.authorities(),
                        cached.additionals()
                );
        }
        System.out.println("Cache MISS for " + question.name());

        DnsHeader requestHeader = query.header();

        int responseFlags = 0x8180;

        DnsHeader responseHeader = new DnsHeader(
                requestHeader.id(),
                responseFlags,
                requestHeader.qdCount(),
                1,
                0,
                0
        );

        byte[] ip = new byte[] {1,2,3,4};

        DnsRecord answer = new DnsRecord(
                question.name(),
                1,
                1,
                300,
                ip
        );

        DnsMessage responseMessage =
        new DnsMessage(
                responseHeader,
                query.questions(),
                List.of(answer),
                List.of(),
                List.of()
        );
        cache.put(question, responseMessage, 300);

        return responseMessage;
    }
}

