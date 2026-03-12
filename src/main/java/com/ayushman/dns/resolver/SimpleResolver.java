package com.ayushman.dns.resolver;
import java.util.List;

import com.ayushman.dns.protocol.DnsHeader;
import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsQuestion;
import com.ayushman.dns.protocol.DnsRecord;

public class SimpleResolver{

    public DnsMessage resolve(DnsMessage query){
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
        DnsQuestion question = query.questions().get(0);
        byte[] ip = new byte[]{1,2,3,4};

        DnsRecord answers = new DnsRecord(
            question.name(),
            1,
            1,
            300,
            ip
        );

        return new DnsMessage(responseHeader, query.questions(), List.of(answers));
    }
}

