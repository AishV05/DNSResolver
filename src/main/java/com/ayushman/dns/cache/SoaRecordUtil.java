package com.ayushman.dns.cache;

import com.ayushman.dns.protocol.DnsRecord;

public final class SoaRecordUtil {

    private SoaRecordUtil() {
    }

    public static long negativeTtl(
            DnsRecord soaRecord
    ) {

        if (soaRecord == null) {
            return 0;
        }

        if (soaRecord.type() != 6) {
            return 0;
        }

        byte[] rdata =
                soaRecord.rdata();

        int position = 0;

        position = skipName(rdata, position);
        position = skipName(rdata, position);

        if (position + 20 > rdata.length) {
            return 0;
        }

        position += 4; // SERIAL
        position += 4; // REFRESH
        position += 4; // RETRY
        position += 4; // EXPIRE

        long minimum =
                readU32(rdata, position);

        long soaTtl =
                soaRecord.ttl();

        return Math.min(
                soaTtl,
                minimum
        );
    }

    private static int skipName(
            byte[] data,
            int position
    ) {

        while (position < data.length) {

            int length =
                    data[position] & 0xFF;

            position++;

            if (length == 0) {
                return position;
            }

            if ((length & 0xC0) == 0xC0) {

                if (position >= data.length) {
                    return data.length;
                }

                return position + 1;
            }

            position += length;
        }

        return position;
    }

    private static long readU32(
            byte[] data,
            int position
    ) {

        return ((long) (data[position] & 0xFF) << 24)
                | ((long) (data[position + 1] & 0xFF) << 16)
                | ((long) (data[position + 2] & 0xFF) << 8)
                | ((long) (data[position + 3] & 0xFF));
    }
}