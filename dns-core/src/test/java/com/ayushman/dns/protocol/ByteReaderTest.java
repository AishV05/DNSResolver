package com.ayushman.dns.protocol;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class ByteReaderTest {

    @Test
    void readsUnsignedPrimitiveValues() {
        ByteReader reader = new ByteReader(new byte[] {
                (byte) 0xFE,
                0x12, 0x34,
                (byte) 0x89, (byte) 0xAB, (byte) 0xCD, (byte) 0xEF
        });

        assertEquals(254, reader.readU8());
        assertEquals(0x1234, reader.readU16());
        assertEquals(0x89ABCDEFL, reader.readU32());
        assertEquals(7, reader.position());
        assertEquals(0, reader.remaining());
    }

    @Test
    void rejectsNullInput() {
        assertThrows(DnsFormatException.class, () -> new ByteReader(null));
    }

    @Test
    void rejectsTruncatedReadsWithoutPartiallyAdvancing() {
        ByteReader u16Reader = new ByteReader(new byte[] {1});
        ByteReader u32Reader = new ByteReader(new byte[] {1, 2, 3});

        assertThrows(DnsFormatException.class, u16Reader::readU16);
        assertThrows(DnsFormatException.class, u32Reader::readU32);
        assertEquals(0, u16Reader.position());
        assertEquals(0, u32Reader.position());
    }

    @Test
    void readsAnExactBoundedByteSequence() {
        ByteReader reader = new ByteReader(new byte[] {1, 2, 3, 4});
        reader.position(1);

        byte[] bytes = reader.readBytes(2);

        assertArrayEquals(new byte[] {2, 3}, bytes);
        assertEquals(3, reader.position());
        assertEquals(1, reader.remaining());
    }

    @Test
    void rejectsInvalidByteCountsWithoutAdvancing() {
        ByteReader reader = new ByteReader(new byte[] {1, 2});

        assertThrows(DnsFormatException.class, () -> reader.readBytes(-1));
        assertThrows(DnsFormatException.class, () -> reader.readBytes(3));
        assertEquals(0, reader.position());
    }

    @Test
    void acceptsEndPositionButRejectsPositionsOutsideThePacket() {
        ByteReader reader = new ByteReader(new byte[] {1, 2});

        reader.position(2);

        assertEquals(2, reader.position());
        assertThrows(DnsFormatException.class, reader::readU8);
        assertThrows(DnsFormatException.class, () -> reader.position(-1));
        assertThrows(DnsFormatException.class, () -> reader.position(3));
        assertEquals(2, reader.position());
    }
}
