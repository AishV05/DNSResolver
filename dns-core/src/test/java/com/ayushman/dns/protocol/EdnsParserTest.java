package com.ayushman.dns.protocol;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.ByteBuffer;

import org.junit.jupiter.api.Test;

public class EdnsParserTest {

    @Test
    void shouldParseOptPayloadSizeAndDnssecOkFlag() {

        DnsMessage message =
                DnsPacketParser.parse(
                        createQueryWithOpt(
                                1_232,
                                0x12,
                                0,
                                EdnsInfo.DNSSEC_OK_FLAG,
                                new byte[0]
                        )
                );

        EdnsInfo edns = message.edns().orElseThrow();

        assertEquals(1_232, edns.udpPayloadSize());
        assertEquals(1_232, edns.effectiveUdpPayloadSize());
        assertEquals(0x12, edns.extendedRcode());
        assertEquals(0, edns.version());
        assertEquals(EdnsInfo.DNSSEC_OK_FLAG, edns.flags());
        assertTrue(edns.dnssecOk());
        assertEquals(0, message.additionals().size());
    }

    @Test
    void shouldParseEdnsVersionAndFlags() {

        DnsMessage message =
                DnsPacketParser.parse(
                        createQueryWithOpt(
                                4_096,
                                0,
                                1,
                                0x1234,
                                new byte[0]
                        )
                );

        EdnsInfo edns = message.edns().orElseThrow();

        assertEquals(4_096, edns.udpPayloadSize());
        assertEquals(1, edns.version());
        assertEquals(0x1234, edns.flags());
        assertEquals(false, edns.dnssecOk());
    }

    @Test
    void shouldPreserveRawEdnsOptions() {

        byte[] options =
                new byte[] {
                        (byte) 0xFD, (byte) 0xE9,
                        0, 2,
                        10, 11
                };

        DnsMessage message =
                DnsPacketParser.parse(
                        createQueryWithOpt(
                                1_232,
                                0,
                                0,
                                0,
                                options
                        )
                );

        EdnsInfo edns = message.edns().orElseThrow();

        assertArrayEquals(options, edns.options());
    }

    @Test
    void shouldUse512AsEffectiveMinimumPayloadSize() {

        DnsMessage message =
                DnsPacketParser.parse(
                        createQueryWithOpt(
                                400,
                                0,
                                0,
                                0,
                                new byte[0]
                        )
                );

        EdnsInfo edns = message.edns().orElseThrow();

        assertEquals(400, edns.udpPayloadSize());
        assertEquals(512, edns.effectiveUdpPayloadSize());
    }

    private byte[] createQueryWithOpt(
            int udpPayloadSize,
            int extendedRcode,
            int version,
            int flags,
            byte[] options
    ) {

        ByteBuffer buffer =
                ByteBuffer.allocate(512);

        buffer.putShort((short) 0x1234);
        buffer.putShort((short) 0x0100);
        buffer.putShort((short) 1);
        buffer.putShort((short) 0);
        buffer.putShort((short) 0);
        buffer.putShort((short) 1);

        DnsNameCodec.encode("example.com", buffer);
        buffer.putShort((short) 1);
        buffer.putShort((short) 1);

        buffer.put((byte) 0);
        buffer.putShort((short) EdnsInfo.OPT_RECORD_TYPE);
        buffer.putShort((short) udpPayloadSize);

        long ttl =
                ((long) extendedRcode << 24)
                        | ((long) version << 16)
                        | flags;

        buffer.putInt((int) ttl);
        buffer.putShort((short) options.length);
        buffer.put(options);

        byte[] packet =
                new byte[buffer.position()];

        buffer.flip();
        buffer.get(packet);

        return packet;
    }
}
