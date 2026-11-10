package com.ayushman.dns.protocol;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.time.Duration;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

class DnsWireRoundTripSafetyTest {

    private static final int QUESTION_NAME_OFFSET = 12;
    private static final Duration PARSE_DEADLINE = Duration.ofSeconds(1);

    @ParameterizedTest(name = "{0}")
    @MethodSource("compressedNameBearingRecords")
    void expandsPacketRelativeRdataBeforeWritingAtANewOffset(
            String caseName,
            int recordType,
            byte[] compressedRdata,
            byte[] expectedNormalizedRdata
    ) {
        DnsMessage parsed = DnsPacketParser.parse(
                packetWithAnswer(recordType, compressedRdata)
        );

        assertEquals(1, parsed.answers().size());
        assertArrayEquals(
                expectedNormalizedRdata,
                parsed.answers().get(0).rdata()
        );

        byte[] rewritten = DnsPacketWriter.buildResponse(parsed);
        DnsMessage reparsed = DnsPacketParser.parse(rewritten);

        assertEquals("example.com", reparsed.answers().get(0).name());
        assertEquals(recordType, reparsed.answers().get(0).type());
        assertArrayEquals(
                expectedNormalizedRdata,
                reparsed.answers().get(0).rdata()
        );
        assertFalse(
                containsSequence(rewritten, pointer(QUESTION_NAME_OFFSET)),
                caseName + " retained a pointer borrowed from the input packet"
        );
    }

    @Test
    void rejectsTrailingBytesAfterDeclaredSections() {
        byte[] validQuery = queryPacket();
        byte[] withTrailingByte = concat(validQuery, new byte[] {42});

        assertBoundedFormatFailure(withTrailingByte);
    }

    @Test
    void rejectsSectionCountsThatCannotFitThePacket() {
        assertBoundedFormatFailure(header(0xFFFF, 0, 0, 0));
        assertBoundedFormatFailure(header(0, 0xFFFF, 0, 0));
        assertBoundedFormatFailure(header(0, 0, 0xFFFF, 0));
        assertBoundedFormatFailure(header(0, 0, 0, 0xFFFF));
    }

    @ParameterizedTest
    @MethodSource("invalidFixedSizeAddressRecords")
    void rejectsInvalidFixedSizeAddressRdata(
            int recordType,
            byte[] rdata
    ) {
        assertBoundedFormatFailure(packetWithAnswer(recordType, rdata));
    }

    @Test
    void rejectsMalformedOptOptionFramingAsAFormatError() {
        byte[] truncatedOptionHeader = new byte[] {0, 1, 0};

        assertBoundedFormatFailure(
                packetWithAdditionalOpt("", truncatedOptionHeader)
        );
    }

    @Test
    void rejectsAnOptRecordWithANonRootOwner() {
        assertBoundedFormatFailure(packetWithAdditionalOpt("not-root", new byte[0]));
    }

    @Test
    void rejectsDuplicateOptRecords() {
        ByteBuffer packet = ByteBuffer.allocate(34);
        packet.put(header(0, 0, 0, 2));
        putOpt(packet, "", new byte[0]);
        putOpt(packet, "", new byte[0]);

        assertBoundedFormatFailure(packet.array());
    }

    private static Stream<Arguments> compressedNameBearingRecords() {
        byte[] soaIntegers = ByteBuffer.allocate(20)
                .putInt(2026102601)
                .putInt(7200)
                .putInt(3600)
                .putInt(1_209_600)
                .putInt(300)
                .array();

        return Stream.of(
                Arguments.of(
                        "NS",
                        2,
                        concat(label("ns"), pointer(QUESTION_NAME_OFFSET)),
                        name("ns", "example", "com")
                ),
                Arguments.of(
                        "CNAME",
                        5,
                        concat(label("target"), pointer(QUESTION_NAME_OFFSET)),
                        name("target", "example", "com")
                ),
                Arguments.of(
                        "PTR",
                        12,
                        concat(label("host"), pointer(QUESTION_NAME_OFFSET)),
                        name("host", "example", "com")
                ),
                Arguments.of(
                        "MX",
                        15,
                        concat(
                                new byte[] {0, 10},
                                label("mail"),
                                pointer(QUESTION_NAME_OFFSET)
                        ),
                        concat(
                                new byte[] {0, 10},
                                name("mail", "example", "com")
                        )
                ),
                Arguments.of(
                        "SOA",
                        6,
                        concat(
                                label("ns"),
                                pointer(QUESTION_NAME_OFFSET),
                                label("hostmaster"),
                                pointer(QUESTION_NAME_OFFSET),
                                soaIntegers
                        ),
                        concat(
                                name("ns", "example", "com"),
                                name("hostmaster", "example", "com"),
                                soaIntegers
                        )
                ),
                Arguments.of(
                        "DNAME",
                        39,
                        concat(label("target"), pointer(QUESTION_NAME_OFFSET)),
                        name("target", "example", "com")
                ),
                Arguments.of(
                        "SRV",
                        33,
                        concat(
                                new byte[] {0, 1, 0, 5, 0x20, (byte) 0xFB},
                                label("service"),
                                pointer(QUESTION_NAME_OFFSET)
                        ),
                        concat(
                                new byte[] {0, 1, 0, 5, 0x20, (byte) 0xFB},
                                name("service", "example", "com")
                        )
                )
        );
    }

    private static Stream<Arguments> invalidFixedSizeAddressRecords() {
        return Stream.of(
                Arguments.of(1, new byte[3]),
                Arguments.of(1, new byte[5]),
                Arguments.of(28, new byte[15]),
                Arguments.of(28, new byte[17])
        );
    }

    private static void assertBoundedFormatFailure(byte[] packet) {
        assertTimeoutPreemptively(
                PARSE_DEADLINE,
                () -> assertThrows(
                        DnsFormatException.class,
                        () -> DnsPacketParser.parse(packet)
                )
        );
    }

    private static byte[] packetWithAnswer(
            int recordType,
            byte[] rdata
    ) {
        ByteBuffer packet = ByteBuffer.allocate(512);
        packet.put(header(1, 1, 0, 0));
        putName(packet, "example", "com");
        packet.putShort((short) 1);
        packet.putShort((short) 1);

        packet.put(pointer(QUESTION_NAME_OFFSET));
        packet.putShort((short) recordType);
        packet.putShort((short) 1);
        packet.putInt(300);
        packet.putShort((short) rdata.length);
        packet.put(rdata);

        return writtenBytes(packet);
    }

    private static byte[] queryPacket() {
        ByteBuffer packet = ByteBuffer.allocate(64);
        packet.put(header(1, 0, 0, 0));
        putName(packet, "example", "com");
        packet.putShort((short) 1);
        packet.putShort((short) 1);
        return writtenBytes(packet);
    }

    private static byte[] packetWithAdditionalOpt(
            String owner,
            byte[] options
    ) {
        ByteBuffer packet = ByteBuffer.allocate(128);
        packet.put(header(0, 0, 0, 1));
        putOpt(packet, owner, options);
        return writtenBytes(packet);
    }

    private static void putOpt(
            ByteBuffer packet,
            String owner,
            byte[] options
    ) {
        if (owner.isEmpty()) {
            packet.put((byte) 0);
        } else {
            putName(packet, owner);
        }
        packet.putShort((short) EdnsInfo.OPT_RECORD_TYPE);
        packet.putShort((short) 1232);
        packet.putInt(0);
        packet.putShort((short) options.length);
        packet.put(options);
    }

    private static byte[] header(
            int questions,
            int answers,
            int authorities,
            int additionals
    ) {
        return ByteBuffer.allocate(12)
                .putShort((short) 0x18B0)
                .putShort((short) 0x8180)
                .putShort((short) questions)
                .putShort((short) answers)
                .putShort((short) authorities)
                .putShort((short) additionals)
                .array();
    }

    private static void putName(ByteBuffer packet, String... labels) {
        packet.put(name(labels));
    }

    private static byte[] name(String... labels) {
        return concat(
                Stream.concat(
                        Stream.of(labels).map(DnsWireRoundTripSafetyTest::label),
                        Stream.of(new byte[] {0})
                ).toArray(byte[][]::new)
        );
    }

    private static byte[] label(String value) {
        byte[] bytes = value.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        return concat(new byte[] {(byte) bytes.length}, bytes);
    }

    private static byte[] pointer(int offset) {
        return new byte[] {
                (byte) (0xC0 | ((offset >>> 8) & 0x3F)),
                (byte) offset
        };
    }

    private static boolean containsSequence(byte[] haystack, byte[] needle) {
        for (int offset = 0; offset <= haystack.length - needle.length; offset++) {
            boolean match = true;
            for (int index = 0; index < needle.length; index++) {
                match &= haystack[offset + index] == needle[index];
            }
            if (match) {
                return true;
            }
        }
        return false;
    }

    private static byte[] writtenBytes(ByteBuffer buffer) {
        byte[] bytes = new byte[buffer.position()];
        buffer.flip();
        buffer.get(bytes);
        return bytes;
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream result = new ByteArrayOutputStream();
        for (byte[] part : parts) {
            result.writeBytes(part);
        }
        return result.toByteArray();
    }
}
