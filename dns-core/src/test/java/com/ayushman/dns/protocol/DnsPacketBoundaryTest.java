package com.ayushman.dns.protocol;

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.nio.ByteBuffer;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class DnsPacketBoundaryTest {

    @Test
    void rejectsNullAndOversizedPacketsAsFormatErrors() {
        assertThrows(
                DnsFormatException.class,
                () -> DnsPacketParser.parse(null)
        );
        assertThrows(
                DnsFormatException.class,
                () -> DnsPacketParser.parse(new byte[65_536])
        );
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2})
    void rejectsOptOutsideTheAdditionalSection(int section) {
        ByteBuffer packet = ByteBuffer.allocate(23);
        packet.putShort((short) 1);
        packet.putShort((short) 0x8180);
        packet.putShort((short) 0);
        packet.putShort((short) (section == 1 ? 1 : 0));
        packet.putShort((short) (section == 2 ? 1 : 0));
        packet.putShort((short) 0);
        putOpt(packet);

        assertThrows(
                DnsFormatException.class,
                () -> DnsPacketParser.parse(packet.array())
        );
    }

    @Test
    void writerRejectsPacketRelativePointersInNameBearingRdata() {
        DnsRecord borrowedPointer = new DnsRecord(
                "example.com",
                2,
                1,
                300,
                new byte[] {(byte) 0xC0, 0x0C}
        );
        DnsMessage message = new DnsMessage(
                new DnsHeader(1, 0x8180, 0, 1, 0, 0),
                List.of(),
                List.of(borrowedPointer),
                List.of(),
                List.of()
        );

        assertThrows(
                DnsFormatException.class,
                () -> DnsPacketWriter.buildResponse(message)
        );
    }

    private static void putOpt(ByteBuffer packet) {
        packet.put((byte) 0);
        packet.putShort((short) EdnsInfo.OPT_RECORD_TYPE);
        packet.putShort((short) 1_232);
        packet.putInt(0);
        packet.putShort((short) 0);
    }
}
