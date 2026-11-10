package com.ayushman.dns.protocol;

import java.util.Objects;

public record DnsRecord(
        String name,
        int type,
        int qclass,
        long ttl,
        byte[] rdata
) {

    public DnsRecord {
        name = Objects.requireNonNull(name, "name");
        rdata = Objects.requireNonNull(rdata, "rdata").clone();
    }

    @Override
    public byte[] rdata() {
        return rdata.clone();
    }
}
