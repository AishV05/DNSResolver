package com.ayushman.dns.protocol;

public record DnsRecord(
    String name,
    int type,
    int qclass,
    int ttl,
    byte[] rdata
){}