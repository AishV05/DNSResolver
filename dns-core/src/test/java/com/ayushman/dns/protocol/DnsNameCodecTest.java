package com.ayushman.dns.protocol;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.nio.ReadOnlyBufferException;
import java.time.Duration;

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
    void shouldEscapeNonPrintableOctetsWhenDecoding() {
        byte[] packet = new byte[] {
                2, (byte) 0x80, (byte) 0xFF, 0
        };

        String name = DnsNameCodec.decode(new ByteReader(packet), packet);

        assertEquals("\\128\\255", name);
    }

    @Test
    void shouldRejectNullOrMismatchedDecoderInput() {
        byte[] packet = {0};

        assertThrows(
                DnsFormatException.class,
                () -> DnsNameCodec.decode(null, packet)
        );
        assertThrows(
                DnsFormatException.class,
                () -> DnsNameCodec.decode(new ByteReader(packet), null)
        );
        assertThrows(
                DnsFormatException.class,
                () -> DnsNameCodec.decode(new ByteReader(packet), packet.clone())
        );
    }

    @Test
    void shouldRejectTruncatedLabelsAndPointers() {
        byte[] truncatedLabel = {3, 'w', 'w'};
        byte[] truncatedPointer = {(byte) 0xC0};

        assertThrows(
                DnsFormatException.class,
                () -> DnsNameCodec.decode(
                        new ByteReader(truncatedLabel),
                        truncatedLabel
                )
        );
        assertThrows(
                DnsFormatException.class,
                () -> DnsNameCodec.decode(
                        new ByteReader(truncatedPointer),
                        truncatedPointer
                )
        );
    }

    @Test
    void shouldRejectOutOfBoundsCompressionPointer() {
        byte[] packet = {(byte) 0xC0, 0x02};

        assertThrows(
                DnsFormatException.class,
                () -> DnsNameCodec.decode(new ByteReader(packet), packet)
        );
    }

    @Test
    void shouldRejectReservedLabelForms() {
        byte[] reserved01 = {0x40, 0};
        byte[] reserved10 = {(byte) 0x80, 0};

        assertThrows(
                DnsFormatException.class,
                () -> DnsNameCodec.decode(new ByteReader(reserved01), reserved01)
        );
        assertThrows(
                DnsFormatException.class,
                () -> DnsNameCodec.decode(new ByteReader(reserved10), reserved10)
        );
    }

    @Test
    void shouldRejectSelfReferentialCompressionPointerPromptly() {
        byte[] packet = {(byte) 0xC0, 0x00};

        assertTimeoutPreemptively(
                Duration.ofSeconds(1),
                () -> assertThrows(
                        DnsFormatException.class,
                        () -> DnsNameCodec.decode(new ByteReader(packet), packet)
                )
        );
    }

    @Test
    void shouldRejectTwoPointerCyclePromptly() {
        byte[] packet = {
                (byte) 0xC0, 0x02,
                (byte) 0xC0, 0x00
        };

        assertTimeoutPreemptively(
                Duration.ofSeconds(1),
                () -> assertThrows(
                        DnsFormatException.class,
                        () -> DnsNameCodec.decode(new ByteReader(packet), packet)
                )
        );
    }

    @Test
    void shouldRejectExcessiveCompressionPointerWorkPromptly() {
        byte[] packet = backwardPointerChain(64);
        ByteReader reader = new ByteReader(packet);
        reader.position(packet.length - 2);

        assertTimeoutPreemptively(
                Duration.ofSeconds(1),
                () -> assertThrows(
                        DnsFormatException.class,
                        () -> DnsNameCodec.decode(reader, packet)
                )
        );
    }

    @Test
    void shouldRejectForwardCompressionPointer() {
        byte[] packet = {
                (byte) 0xC0, 0x02,
                0
        };

        assertThrows(
                DnsFormatException.class,
                () -> DnsNameCodec.decode(new ByteReader(packet), packet)
        );
    }

    @Test
    void shouldAllowTheMaximumExpandedNameLength() {
        byte[] packet = encodedName(63, 63, 63, 61);

        String decoded = DnsNameCodec.decode(new ByteReader(packet), packet);

        assertEquals(253, decoded.length());
    }

    @Test
    void shouldRejectExpandedNamesLongerThan255WireOctets() {
        byte[] packet = encodedName(63, 63, 63, 63);

        assertThrows(
                DnsFormatException.class,
                () -> DnsNameCodec.decode(new ByteReader(packet), packet)
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

    @Test
    void shouldEncodeRootNameWrittenAsDot() {
        ByteBuffer buffer = ByteBuffer.allocate(1);

        DnsNameCodec.encode(".", buffer);

        assertArrayEquals(new byte[] {0}, buffer.array());
    }

    @Test
    void shouldAcceptAValidTrailingDot() {
        ByteBuffer relative = ByteBuffer.allocate(32);
        ByteBuffer absolute = ByteBuffer.allocate(32);

        DnsNameCodec.encode("example.com", relative);
        DnsNameCodec.encode("example.com.", absolute);

        assertEquals(relative.position(), absolute.position());
        assertArrayEquals(
                bytesWritten(relative),
                bytesWritten(absolute)
        );
    }

    @Test
    void shouldRoundTripEscapedLabelOctetsWithoutAmbiguity() {
        byte[] packet = {
                8,
                'a', '.', 'b', '\\', 0, ' ', (byte) 0x80, (byte) 0xFF,
                0
        };

        String decoded = DnsNameCodec.decode(new ByteReader(packet), packet);
        ByteBuffer encoded = ByteBuffer.allocate(packet.length);
        DnsNameCodec.encode(decoded, encoded);

        assertEquals(
                "a\\." + "b" + "\\\\" + "\\000" + "\\032" + "\\128" + "\\255",
                decoded
        );
        assertArrayEquals(packet, encoded.array());
    }

    @Test
    void shouldRejectMalformedPresentationNamesBeforeWriting() {
        String[] invalidNames = {
                "a..b",
                ".example",
                "example\\",
                "example\\12",
                "example\\999",
                "example\\q",
                "white space",
                "caf\u00e9.example"
        };

        for (String name : invalidNames) {
            ByteBuffer buffer = ByteBuffer.allocate(512);

            assertThrows(
                    IllegalArgumentException.class,
                    () -> DnsNameCodec.encode(name, buffer),
                    name
            );
            assertEquals(0, buffer.position(), name);
        }
    }

    @Test
    void shouldRejectNullEncoderInputs() {
        assertThrows(
                IllegalArgumentException.class,
                () -> DnsNameCodec.encode(null, ByteBuffer.allocate(1))
        );
        assertThrows(
                NullPointerException.class,
                () -> DnsNameCodec.encode("", null)
        );
    }

    @Test
    void shouldEnforceEncodedLabelAndNameLimitsBeforeWriting() {
        String oversizedLabel = "a".repeat(64);
        String oversizedName = String.join(
                ".",
                "a".repeat(63),
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(63)
        );

        ByteBuffer labelBuffer = ByteBuffer.allocate(512);
        ByteBuffer nameBuffer = ByteBuffer.allocate(512);

        assertThrows(
                IllegalArgumentException.class,
                () -> DnsNameCodec.encode(oversizedLabel, labelBuffer)
        );
        assertThrows(
                IllegalArgumentException.class,
                () -> DnsNameCodec.encode(oversizedName, nameBuffer)
        );
        assertEquals(0, labelBuffer.position());
        assertEquals(0, nameBuffer.position());
    }

    @Test
    void shouldEncodeTheMaximumWireNameLength() {
        String maximumName = String.join(
                ".",
                "a".repeat(63),
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(61)
        );
        ByteBuffer buffer = ByteBuffer.allocate(255);

        DnsNameCodec.encode(maximumName, buffer);

        assertEquals(255, buffer.position());
    }

    @Test
    void shouldRejectInsufficientOrReadOnlyBuffersBeforeWriting() {
        ByteBuffer tooSmall = ByteBuffer.allocate(5);
        tooSmall.put((byte) 99);
        ByteBuffer readOnly = ByteBuffer.allocate(32).asReadOnlyBuffer();

        assertThrows(
                BufferOverflowException.class,
                () -> DnsNameCodec.encode("com", tooSmall)
        );
        assertThrows(
                ReadOnlyBufferException.class,
                () -> DnsNameCodec.encode("com", readOnly)
        );
        assertEquals(1, tooSmall.position());
        assertEquals(0, readOnly.position());
    }

    private static byte[] backwardPointerChain(int pointerCount) {
        ByteBuffer packet = ByteBuffer.allocate((pointerCount * 2) + 1);
        packet.put((byte) 0);
        for (int pointer = 0; pointer < pointerCount; pointer++) {
            int target = pointer == 0 ? 0 : (pointer * 2) - 1;
            packet.put((byte) (0xC0 | ((target >>> 8) & 0x3F)));
            packet.put((byte) target);
        }
        return packet.array();
    }

    private static byte[] bytesWritten(ByteBuffer buffer) {
        byte[] bytes = new byte[buffer.position()];
        buffer.flip();
        buffer.get(bytes);
        return bytes;
    }

    private static byte[] encodedName(int... labelLengths) {
        int wireLength = 1;
        for (int labelLength : labelLengths) {
            wireLength += labelLength + 1;
        }

        ByteBuffer packet = ByteBuffer.allocate(wireLength);
        for (int label = 0; label < labelLengths.length; label++) {
            packet.put((byte) labelLengths[label]);
            for (int octet = 0; octet < labelLengths[label]; octet++) {
                packet.put((byte) ('a' + label));
            }
        }
        packet.put((byte) 0);
        return packet.array();
    }
}
