package com.ayushman.dns.protocol;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Malformed packets shared by parser hardening tests.
 *
 * <p>Every fixture is safe to execute against the bounded decoder. The catalog
 * remains shared so later fuzzing and transport tests use the same regression
 * inputs.</p>
 */
final class AdversarialDnsPacketCorpus {

    enum Category {
        TRUNCATED_HEADER,
        SELF_COMPRESSION_POINTER,
        COMPRESSION_POINTER_CYCLE,
        EXCESSIVE_COMPRESSION_POINTER_CHAIN,
        OUT_OF_BOUNDS_POINTER,
        RESERVED_LABEL_FORM,
        EXPANDED_NAME_TOO_LONG,
        IMPOSSIBLE_SECTION_COUNT,
        TRUNCATED_RDATA
    }

    enum ParserBaseline {
        ASSERT_REJECTS_NOW
    }

    enum ExpectedDisposition {
        REJECT_AS_FORMAT_ERROR
    }

    record Fixture(
            String id,
            Category category,
            ExpectedDisposition expectedDisposition,
            ParserBaseline parserBaseline,
            String reason,
            byte[] wireBytes
    ) {
        Fixture {
            Objects.requireNonNull(id, "id");
            Objects.requireNonNull(category, "category");
            Objects.requireNonNull(expectedDisposition, "expectedDisposition");
            Objects.requireNonNull(parserBaseline, "parserBaseline");
            Objects.requireNonNull(reason, "reason");
            Objects.requireNonNull(wireBytes, "wireBytes");

            if (id.isBlank()) {
                throw new IllegalArgumentException("fixture id must not be blank");
            }
            if (reason.isBlank()) {
                throw new IllegalArgumentException("fixture reason must not be blank");
            }

            wireBytes = wireBytes.clone();
        }

        @Override
        public byte[] wireBytes() {
            return wireBytes.clone();
        }
    }

    private static final List<Fixture> FIXTURES = List.of(
            fixture(
                    "truncated-header",
                    Category.TRUNCATED_HEADER,
                    ParserBaseline.ASSERT_REJECTS_NOW,
                    "The DNS header ends before ARCOUNT.",
                    new byte[11]
            ),
            fixture(
                    "self-compression-pointer",
                    Category.SELF_COMPRESSION_POINTER,
                    ParserBaseline.ASSERT_REJECTS_NOW,
                    "QNAME points back to its own first octet.",
                    queryWithName(new byte[] {(byte) 0xC0, 0x0C})
            ),
            fixture(
                    "two-pointer-compression-cycle",
                    Category.COMPRESSION_POINTER_CYCLE,
                    ParserBaseline.ASSERT_REJECTS_NOW,
                    "The pointers at offsets 12 and 14 point to each other.",
                    packetWithPointerCycle()
            ),
            fixture(
                    "excessive-compression-pointer-chain",
                    Category.EXCESSIVE_COMPRESSION_POINTER_CHAIN,
                    ParserBaseline.ASSERT_REJECTS_NOW,
                    "QNAME requires 64 compression-pointer jumps.",
                    packetWithPointerChain(64)
            ),
            fixture(
                    "out-of-bounds-compression-pointer",
                    Category.OUT_OF_BOUNDS_POINTER,
                    ParserBaseline.ASSERT_REJECTS_NOW,
                    "QNAME points beyond the end of the message.",
                    queryWithName(new byte[] {(byte) 0xC0, (byte) 0xFF})
            ),
            fixture(
                    "reserved-label-form",
                    Category.RESERVED_LABEL_FORM,
                    ParserBaseline.ASSERT_REJECTS_NOW,
                    "A label starts with the reserved 01 bit pattern.",
                    queryWithName(reservedLabelName())
            ),
            fixture(
                    "expanded-name-over-255-octets",
                    Category.EXPANDED_NAME_TOO_LONG,
                    ParserBaseline.ASSERT_REJECTS_NOW,
                    "Four 63-octet labels exceed the 255-octet DNS name limit.",
                    queryWithName(overlongName())
            ),
            fixture(
                    "impossible-question-count",
                    Category.IMPOSSIBLE_SECTION_COUNT,
                    ParserBaseline.ASSERT_REJECTS_NOW,
                    "QDCOUNT declares 65,535 questions but no question bytes follow.",
                    header(0xFFFF, 0, 0, 0)
            ),
            fixture(
                    "rdata-shorter-than-rdlength",
                    Category.TRUNCATED_RDATA,
                    ParserBaseline.ASSERT_REJECTS_NOW,
                    "An A record declares four RDATA octets but carries only three.",
                    packetWithTruncatedRdata()
            )
    );

    private AdversarialDnsPacketCorpus() {
    }

    static List<Fixture> all() {
        return FIXTURES;
    }

    private static Fixture fixture(
            String id,
            Category category,
            ParserBaseline parserBaseline,
            String reason,
            byte[] wireBytes
    ) {
        return new Fixture(
                id,
                category,
                ExpectedDisposition.REJECT_AS_FORMAT_ERROR,
                parserBaseline,
                reason,
                wireBytes
        );
    }

    private static byte[] queryWithName(byte[] encodedName) {
        ByteBuffer packet = ByteBuffer.allocate(12 + encodedName.length + 4);
        packet.put(header(1, 0, 0, 0));
        packet.put(encodedName);
        packet.putShort((short) 1);
        packet.putShort((short) 1);
        return packet.array();
    }

    private static byte[] packetWithPointerCycle() {
        ByteBuffer packet = ByteBuffer.allocate(20);
        packet.put(header(1, 0, 0, 0));
        packet.put((byte) 0xC0).put((byte) 0x0E);
        packet.put((byte) 0xC0).put((byte) 0x0C);
        packet.putShort((short) 1);
        packet.putShort((short) 1);
        return packet.array();
    }

    private static byte[] packetWithPointerChain(
            int pointerCount
    ) {
        int chainStart = 18;
        int terminalOffset = chainStart + (pointerCount * 2);

        ByteBuffer packet = ByteBuffer.allocate(terminalOffset + 1);
        packet.put(header(1, 0, 0, 0));
        putPointer(packet, chainStart);
        packet.putShort((short) 1);
        packet.putShort((short) 1);

        for (int pointer = 0; pointer < pointerCount; pointer++) {
            putPointer(packet, chainStart + ((pointer + 1) * 2));
        }

        packet.put((byte) 0);
        return packet.array();
    }

    private static void putPointer(
            ByteBuffer packet,
            int target
    ) {
        packet.put((byte) (0xC0 | ((target >>> 8) & 0x3F)));
        packet.put((byte) target);
    }

    private static byte[] reservedLabelName() {
        byte[] name = new byte[66];
        name[0] = 0x40;
        Arrays.fill(name, 1, 65, (byte) 'a');
        name[65] = 0;
        return name;
    }

    private static byte[] overlongName() {
        ByteBuffer name = ByteBuffer.allocate(257);
        for (int label = 0; label < 4; label++) {
            name.put((byte) 63);
            for (int octet = 0; octet < 63; octet++) {
                name.put((byte) ('a' + label));
            }
        }
        name.put((byte) 0);
        return name.array();
    }

    private static byte[] packetWithTruncatedRdata() {
        ByteBuffer packet = ByteBuffer.allocate(26);
        packet.put(header(0, 1, 0, 0));
        packet.put((byte) 0);
        packet.putShort((short) 1);
        packet.putShort((short) 1);
        packet.putInt(60);
        packet.putShort((short) 4);
        packet.put(new byte[] {10, 20, 30});
        return packet.array();
    }

    private static byte[] header(int questions, int answers, int authorities, int additionals) {
        return ByteBuffer.allocate(12)
                .putShort((short) 0x18A0)
                .putShort((short) 0x0100)
                .putShort((short) questions)
                .putShort((short) answers)
                .putShort((short) authorities)
                .putShort((short) additionals)
                .array();
    }
}
