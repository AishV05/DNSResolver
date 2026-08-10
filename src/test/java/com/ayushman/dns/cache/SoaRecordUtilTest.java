package com.ayushman.dns.cache;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import com.ayushman.dns.protocol.DnsRecord;

public class SoaRecordUtilTest {

    @Test
    void shouldReturnMinimumWhenMinimumIsLowerThanTtl() {

        byte[] rdata = new byte[] {
                1, 'a', 0,
                1, 'b', 0,

                0, 0, 0, 1,
                0, 0, 0, 2,
                0, 0, 0, 3,
                0, 0, 0, 4,

                0, 0, 1, 44
        };

        DnsRecord soa =
                new DnsRecord(
                        "example.com",
                        6,
                        1,
                        900,
                        rdata
                );

        long result =
                SoaRecordUtil.negativeTtl(soa);

        assertEquals(300, result);
    }

    @Test
    void shouldReturnSoaTtlWhenTtlIsLowerThanMinimum() {

        byte[] rdata = new byte[] {
                1, 'a', 0,
                1, 'b', 0,

                0, 0, 0, 1,
                0, 0, 0, 2,
                0, 0, 0, 3,
                0, 0, 0, 4,

                0, 0, 3, (byte) 132
        };

        DnsRecord soa =
                new DnsRecord(
                        "example.com",
                        6,
                        1,
                        300,
                        rdata
                );

        long result =
                SoaRecordUtil.negativeTtl(soa);

        assertEquals(300, result);
    }

    @Test
    void shouldReturnZeroForNonSoaRecord() {

        DnsRecord record =
                new DnsRecord(
                        "example.com",
                        1,
                        1,
                        300,
                        new byte[] {
                                1, 2, 3, 4
                        }
                );

        long result =
                SoaRecordUtil.negativeTtl(record);

        assertEquals(0, result);
    }

    @Test
    void shouldReturnZeroForNullRecord() {

        long result =
                SoaRecordUtil.negativeTtl(null);

        assertEquals(0, result);
    }
}