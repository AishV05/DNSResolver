package com.ayushman.dns.protocol;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.util.List;

import org.junit.jupiter.api.Test;

public class EdnsWriterTest {

    @Test
    void shouldWriteOptRecordInQuery() {

        byte[] options =
                new byte[] {
                        0, 10,
                        0, 2,
                        1, 2
                };

        DnsMessage query =
                createMessage(
                        List.of(),
                        new EdnsInfo(
                                1_232,
                                0x12,
                                0,
                                EdnsInfo.DNSSEC_OK_FLAG,
                                options
                        )
                );

        DnsMessage parsed =
                DnsPacketParser.parse(
                        DnsPacketWriter.buildQuery(query)
                );

        EdnsInfo edns = parsed.edns().orElseThrow();

        assertEquals(1, parsed.header().arCount());
        assertEquals(1_232, edns.udpPayloadSize());
        assertEquals(0x12, edns.extendedRcode());
        assertEquals(0, edns.version());
        assertEquals(EdnsInfo.DNSSEC_OK_FLAG, edns.flags());
        assertArrayEquals(options, edns.options());
    }

    @Test
    void shouldWriteOptAfterNormalAdditionalRecords() {

        DnsRecord additional =
                new DnsRecord(
                        "ns.example.com",
                        1,
                        1,
                        300,
                        new byte[] {
                                (byte) 192, 0, 2, 1
                        }
                );

        DnsMessage response =
                createMessage(
                        List.of(additional),
                        new EdnsInfo(
                                4_096,
                                0,
                                0,
                                0,
                                new byte[0]
                        )
                );

        DnsMessage parsed =
                DnsPacketParser.parse(
                        DnsPacketWriter.buildResponse(response)
                );

        assertEquals(2, parsed.header().arCount());
        assertEquals(1, parsed.additionals().size());
        assertEquals(
                "ns.example.com",
                parsed.additionals().get(0).name()
        );
        assertEquals(4_096, parsed.edns().orElseThrow().udpPayloadSize());
    }

    private DnsMessage createMessage(
            List<DnsRecord> additionals,
            EdnsInfo edns
    ) {

        DnsQuestion question =
                new DnsQuestion(
                        "example.com",
                        1,
                        1
                );

        return new DnsMessage(
                new DnsHeader(
                        0x1234,
                        0x0100,
                        1,
                        0,
                        0,
                        0
                ),
                List.of(question),
                List.of(),
                List.of(),
                additionals,
                edns
        );
    }
}
