package com.ayushman.dns.protocol;

public record DnsRecord(
    String name,
    int type,
    int qclass,
    long ttl,
    byte[] rdata
){}