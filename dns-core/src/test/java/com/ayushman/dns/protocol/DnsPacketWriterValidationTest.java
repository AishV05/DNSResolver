package com.ayushman.dns.protocol;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.List;

import org.junit.jupiter.api.Test;

class DnsPacketWriterValidationTest {

    @Test
    void rejectsHeaderFieldsOutsideUnsigned16Range() {
        DnsMessage invalidId = message(
                new DnsHeader(65_536, 0, 0, 0, 0, 0),
                List.of(),
                List.of()
        );
        DnsMessage invalidFlags = message(
                new DnsHeader(1, -1, 0, 0, 0, 0),
                List.of(),
                List.of()
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> DnsPacketWriter.buildResponse(invalidId)
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> DnsPacketWriter.buildResponse(invalidFlags)
        );
    }

    @Test
    void rejectsQuestionFieldsOutsideUnsigned16Range() {
        DnsMessage invalidType = message(
                header(),
                List.of(new DnsQuestion("example.com", 65_536, 1)),
                List.of()
        );
        DnsMessage invalidClass = message(
                header(),
                List.of(new DnsQuestion("example.com", 1, -1)),
                List.of()
        );

        assertThrows(
                IllegalArgumentException.class,
                () -> DnsPacketWriter.buildQuery(invalidType)
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> DnsPacketWriter.buildQuery(invalidClass)
        );
    }

    @Test
    void rejectsRecordFieldsOutsideWireRanges() {
        DnsRecord invalidClass = record(16, -1, 0, new byte[0]);
        DnsRecord invalidTtl = record(16, 1, 0x1_0000_0000L, new byte[0]);
        DnsRecord oversizedRdata = record(16, 1, 0, new byte[65_536]);

        assertRecordRejected(invalidClass);
        assertRecordRejected(invalidTtl);
        assertRecordRejected(oversizedRdata);
    }

    @Test
    void reportsAnEncodedMessageThatExceedsTheDnsWireLimit() {
        DnsRecord almostFullPacket = record(16, 1, 0, new byte[65_520]);

        assertThrows(
                IllegalArgumentException.class,
                () -> DnsPacketWriter.buildResponse(
                        message(header(), List.of(), List.of(almostFullPacket))
                )
        );
    }

    private static void assertRecordRejected(DnsRecord record) {
        assertThrows(
                IllegalArgumentException.class,
                () -> DnsPacketWriter.buildResponse(
                        message(header(), List.of(), List.of(record))
                )
        );
    }

    private static DnsRecord record(
            int type,
            int qclass,
            long ttl,
            byte[] rdata
    ) {
        return new DnsRecord("example.com", type, qclass, ttl, rdata);
    }

    private static DnsHeader header() {
        return new DnsHeader(1, 0x8180, 0, 0, 0, 0);
    }

    private static DnsMessage message(
            DnsHeader header,
            List<DnsQuestion> questions,
            List<DnsRecord> answers
    ) {
        return new DnsMessage(
                header,
                questions,
                answers,
                List.of(),
                List.of()
        );
    }
}
