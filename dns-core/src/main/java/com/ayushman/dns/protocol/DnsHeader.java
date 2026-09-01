package com.ayushman.dns.protocol;

public record DnsHeader(
    int id,
    int flags,
    int qdCount,
    int anCount,
    int nsCount,
    int arCount
){}