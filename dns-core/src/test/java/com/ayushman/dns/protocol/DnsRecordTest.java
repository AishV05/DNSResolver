package com.ayushman.dns.protocol;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class DnsRecordTest {

    @Test
    void ownsItsRdataAndNeverExposesTheStoredArray() {
        byte[] source = new byte[] {1, 2, 3, 4};
        DnsRecord record = new DnsRecord(
                "example.com",
                1,
                1,
                300,
                source
        );

        source[0] = 99;
        byte[] returned = record.rdata();
        returned[1] = 88;

        assertArrayEquals(new byte[] {1, 2, 3, 4}, record.rdata());
    }

    @Test
    void rejectsNullReferenceFields() {
        assertThrows(
                NullPointerException.class,
                () -> new DnsRecord(null, 1, 1, 300, new byte[4])
        );
        assertThrows(
                NullPointerException.class,
                () -> new DnsRecord("example.com", 1, 1, 300, null)
        );
    }
}
