package com.ayushman.dns.protocol;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.ByteBuffer;

import org.junit.jupiter.api.Test;

public class DnsNameCodecTest {

    @Test
    void shouldDecodeSimpleName() {

        byte[] packet = new byte[] {
                3, 'w', 'w', 'w',
                5, 'y', 'a', 'h', 'o', 'o',
                3, 'c', 'o', 'm',
                0
        };

        ByteReader reader =
                new ByteReader(packet);

        String name =
                DnsNameCodec.decode(
                        reader,
                        packet
                );

        assertEquals(
                "www.yahoo.com",
                name
        );
    }

    @Test
    void shouldDecodeSingleLabelName() {

        byte[] packet = new byte[] {
                3, 'c', 'o', 'm',
                0
        };

        ByteReader reader =
                new ByteReader(packet);

        String name =
                DnsNameCodec.decode(
                        reader,
                        packet
                );

        assertEquals(
                "com",
                name
        );
    }

    @Test
    void shouldDecodeRootName() {

        byte[] packet = new byte[] {
                0
        };

        ByteReader reader =
                new ByteReader(packet);

        String name =
                DnsNameCodec.decode(
                        reader,
                        packet
                );

        assertEquals(
                "",
                name
        );
    }

    @Test
    void shouldDecodeCompressedName() {

        byte[] packet = new byte[] {
                3, 'c', 'o', 'm',
                0,

                3, 'w', 'w', 'w',
                (byte) 0xC0, 0x00
        };

        ByteReader reader =
                new ByteReader(packet);

        reader.position(5);

        String name =
                DnsNameCodec.decode(
                        reader,
                        packet
                );

        assertEquals(
                "www.com",
                name
        );
    }

    @Test
    void shouldAdvanceReaderPastCompressionPointer() {

        byte[] packet = new byte[] {
                3, 'c', 'o', 'm',
                0,

                3, 'w', 'w', 'w',
                (byte) 0xC0, 0x00
        };

        ByteReader reader =
                new ByteReader(packet);

        reader.position(5);

        DnsNameCodec.decode(
                reader,
                packet
        );

        assertEquals(
                11,
                reader.position()
        );
    }

    @Test
    void shouldEncodeSimpleName() {

        ByteBuffer buffer =
                ByteBuffer.allocate(100);

        DnsNameCodec.encode(
                "www.example.com",
                buffer
        );

        byte[] actual =
                new byte[buffer.position()];

        buffer.flip();
        buffer.get(actual);

        byte[] expected = new byte[] {
                3, 'w', 'w', 'w',
                7, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
                3, 'c', 'o', 'm',
                0
        };

        assertArrayEquals(
                expected,
                actual
        );
    }

    @Test
    void shouldEncodeRootName() {

        ByteBuffer buffer =
                ByteBuffer.allocate(10);

        DnsNameCodec.encode(
                "",
                buffer
        );

        byte[] actual =
                new byte[buffer.position()];

        buffer.flip();
        buffer.get(actual);

        byte[] expected = new byte[] {
                0
        };

        assertArrayEquals(
                expected,
                actual
        );
    }
}