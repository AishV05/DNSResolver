package com.ayushman.dns.protocol;
public record DnsQuestion(
    String name,
    int type,
    int qclass
){}