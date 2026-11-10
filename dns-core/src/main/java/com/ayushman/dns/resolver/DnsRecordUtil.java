package com.ayushman.dns.resolver;

import java.net.InetAddress;
import java.net.UnknownHostException;

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

        byte[] data = record.rdata();
        ByteReader reader = new ByteReader(data);

        String name = DnsNameCodec.decode(
                reader,
                data
        );

        if (reader.remaining() != 0) {
            return null;
        }

        return name;
    }

    public static String getIpAddress(DnsRecord record) {
        byte[] data = record.rdata();

        if (record.type() != 1 && record.type() != 28) {
            return null;
        }

        if ((record.type() == 1 && data.length != 4)
                || (record.type() == 28 && data.length != 16)) {
            return null;
        }

        try {
            return InetAddress.getByAddress(data).getHostAddress();
        } catch (UnknownHostException impossibleLength) {
            return null;
        }
    }
}
