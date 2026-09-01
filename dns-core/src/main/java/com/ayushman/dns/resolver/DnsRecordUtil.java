package com.ayushman.dns.resolver;

import com.ayushman.dns.protocol.ByteReader;
import com.ayushman.dns.protocol.DnsNameCodec;
import com.ayushman.dns.protocol.DnsRecord;

public final class DnsRecordUtil {

    private DnsRecordUtil() {}

    public static String getIpv4Address(DnsRecord record) {

        byte[] data = record.rdata();

        if (data.length != 4) {
            return null;
        }

        return (data[0] & 0xFF) + "."
                + (data[1] & 0xFF) + "."
                + (data[2] & 0xFF) + "."
                + (data[3] & 0xFF);
    }

    public static String getDomainName(DnsRecord record) {

        ByteReader reader =
                new ByteReader(record.rdata());

        return DnsNameCodec.decode(
                reader,
                record.rdata()
        );
    }
}