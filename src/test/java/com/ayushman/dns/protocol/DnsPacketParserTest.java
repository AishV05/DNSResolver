package com.ayushman.dns.protocol;

import static org.junit.jupiter.api.Assertions.assertEquals;

import java.nio.ByteBuffer;

import org.junit.jupiter.api.Test;

public class DnsPacketParserTest {

    @Test
    void shouldParseHeaderCorrectly() {

        DnsMessage message =
                DnsPacketParser.parse(
                        TestPackets.GOOGLE_QUERY
                );

        DnsHeader header =
                message.header();

        assertEquals(
                0x1234,
                header.id()
        );

        assertEquals(
                1,
                header.qdCount()
        );

        assertEquals(
                0,
                header.anCount()
        );

        assertEquals(
                0,
                header.nsCount()
        );

        assertEquals(
                0,
                header.arCount()
        );
    }

    @Test
    void shouldParseQuestionCorrectly() {

        DnsMessage message =
                DnsPacketParser.parse(
                        TestPackets.GOOGLE_QUERY
                );

        assertEquals(
                1,
                message.questions().size()
        );

        DnsQuestion question =
                message.questions().get(0);

        assertEquals(
                "google.com",
                question.name()
        );

        assertEquals(
                1,
                question.type()
        );

        assertEquals(
                1,
                question.qclass()
        );
    }

    @Test
    void shouldParseARecord() {

        byte[] packet =
                createARecordPacket();

        DnsMessage message =
                DnsPacketParser.parse(packet);

        assertEquals(
                1,
                message.answers().size()
        );

        DnsRecord record =
                message.answers().get(0);

        assertEquals(
                "example.com",
                record.name()
        );

        assertEquals(
                1,
                record.type()
        );

        assertEquals(
                1,
                record.qclass()
        );

        assertEquals(
                300,
                record.ttl()
        );

        assertEquals(
                4,
                record.rdata().length
        );

        assertEquals(
                1,
                record.rdata()[0] & 0xFF
        );

        assertEquals(
                2,
                record.rdata()[1] & 0xFF
        );

        assertEquals(
                3,
                record.rdata()[2] & 0xFF
        );

        assertEquals(
                4,
                record.rdata()[3] & 0xFF
        );
    }

    @Test
    void shouldParseMxRecord() {

        byte[] packet =
                createMxRecordPacket();

        DnsMessage message =
                DnsPacketParser.parse(packet);

        assertEquals(
                1,
                message.answers().size()
        );

        DnsRecord record =
                message.answers().get(0);

        assertEquals(
                "example.com",
                record.name()
        );

        assertEquals(
                15,
                record.type()
        );

        assertEquals(
                1,
                record.qclass()
        );

        assertEquals(
                300,
                record.ttl()
        );

        assertEquals(
                10,
                ((record.rdata()[0] & 0xFF) << 8)
                        | (record.rdata()[1] & 0xFF)
        );
    }

    @Test
    void shouldParseAaaaRecord() {

        byte[] packet =
                createAaaaRecordPacket();

        DnsMessage message =
                DnsPacketParser.parse(packet);

        assertEquals(
                1,
                message.answers().size()
        );

        DnsRecord record =
                message.answers().get(0);

        assertEquals(
                "example.com",
                record.name()
        );

        assertEquals(
                28,
                record.type()
        );

        assertEquals(
                1,
                record.qclass()
        );

        assertEquals(
                300,
                record.ttl()
        );

        assertEquals(
                16,
                record.rdata().length
        );
    }

    @Test
    void shouldParseAuthorityRecord() {

        byte[] packet =
                createAuthorityPacket();

        DnsMessage message =
                DnsPacketParser.parse(packet);

        assertEquals(
                0,
                message.answers().size()
        );

        assertEquals(
                1,
                message.authorities().size()
        );

        DnsRecord record =
                message.authorities().get(0);

        assertEquals(
                "example.com",
                record.name()
        );

        assertEquals(
                6,
                record.type()
        );

        assertEquals(
                1,
                record.qclass()
        );

        assertEquals(
                900,
                record.ttl()
        );
    }

    @Test
    void shouldParseAdditionalRecord() {

        byte[] packet =
                createAdditionalPacket();

        DnsMessage message =
                DnsPacketParser.parse(packet);

        assertEquals(
                0,
                message.answers().size()
        );

        assertEquals(
                0,
                message.authorities().size()
        );

        assertEquals(
                1,
                message.additionals().size()
        );

        DnsRecord record =
                message.additionals().get(0);

        assertEquals(
                "ns.example.com",
                record.name()
        );

        assertEquals(
                1,
                record.type()
        );

        assertEquals(
                1,
                record.qclass()
        );

        assertEquals(
                4,
                record.rdata().length
        );
    }

    @Test
    void shouldParseCompressedRecordName() {

        byte[] packet =
                createCompressedARecordPacket();

        DnsMessage message =
                DnsPacketParser.parse(packet);

        assertEquals(
                1,
                message.answers().size()
        );

        DnsRecord record =
                message.answers().get(0);

        assertEquals(
                "www.example.com",
                record.name()
        );

        assertEquals(
                1,
                record.type()
        );

        assertEquals(
                1,
                record.qclass()
        );

        assertEquals(
                4,
                record.rdata().length
        );
    }

    private byte[] createARecordPacket() {

        ByteBuffer buffer =
                ByteBuffer.allocate(512);

        writeHeader(
                buffer,
                0x1234,
                0x8180,
                1,
                1,
                0,
                0
        );

        writeName(
                buffer,
                "example.com"
        );

        buffer.putShort(
                (short) 1
        );

        buffer.putShort(
                (short) 1
        );

        writeName(
                buffer,
                "example.com"
        );

        buffer.putShort(
                (short) 1
        );

        buffer.putShort(
                (short) 1
        );

        buffer.putInt(
                300
        );

        buffer.putShort(
                (short) 4
        );

        buffer.put(
                new byte[] {
                        1, 2, 3, 4
                }
        );

        return slice(buffer);
    }

    private byte[] createMxRecordPacket() {

        ByteBuffer buffer =
                ByteBuffer.allocate(512);

        writeHeader(
                buffer,
                0x1234,
                0x8180,
                1,
                1,
                0,
                0
        );

        writeName(
                buffer,
                "example.com"
        );

        buffer.putShort(
                (short) 15
        );

        buffer.putShort(
                (short) 1
        );

        writeName(
                buffer,
                "example.com"
        );

        buffer.putShort(
                (short) 15
        );

        buffer.putShort(
                (short) 1
        );

        buffer.putInt(
                300
        );

        byte[] exchange =
                encodeName("mail.example.com");

        buffer.putShort(
                (short) (2 + exchange.length)
        );

        buffer.putShort(
                (short) 10
        );

        buffer.put(exchange);

        return slice(buffer);
    }

    private byte[] createAaaaRecordPacket() {

        ByteBuffer buffer =
                ByteBuffer.allocate(512);

        writeHeader(
                buffer,
                0x1234,
                0x8180,
                1,
                1,
                0,
                0
        );

        writeName(
                buffer,
                "example.com"
        );

        buffer.putShort(
                (short) 28
        );

        buffer.putShort(
                (short) 1
        );

        writeName(
                buffer,
                "example.com"
        );

        buffer.putShort(
                (short) 28
        );

        buffer.putShort(
                (short) 1
        );

        buffer.putInt(
                300
        );

        buffer.putShort(
                (short) 16
        );

        buffer.put(
                new byte[] {
                        0x20, 0x01,
                        0x0D, (byte) 0xB8,
                        0, 0,
                        0, 0,
                        0, 0,
                        0, 0,
                        0, 0,
                        0, 1
                }
        );

        return slice(buffer);
    }

    private byte[] createAuthorityPacket() {

        ByteBuffer buffer =
                ByteBuffer.allocate(512);

        writeHeader(
                buffer,
                0x1234,
                0x8400,
                1,
                0,
                1,
                0
        );

        writeName(
                buffer,
                "example.com"
        );

        buffer.putShort(
                (short) 1
        );

        buffer.putShort(
                (short) 1
        );

        writeName(
                buffer,
                "example.com"
        );

        buffer.putShort(
                (short) 6
        );

        buffer.putShort(
                (short) 1
        );

        buffer.putInt(
                900
        );

        buffer.putShort(
                (short) 0
        );

        return slice(buffer);
    }

    private byte[] createAdditionalPacket() {

        ByteBuffer buffer =
                ByteBuffer.allocate(512);

        writeHeader(
                buffer,
                0x1234,
                0x8180,
                1,
                0,
                0,
                1
        );

        writeName(
                buffer,
                "example.com"
        );

        buffer.putShort(
                (short) 1
        );

        buffer.putShort(
                (short) 1
        );

        writeName(
                buffer,
                "ns.example.com"
        );

        buffer.putShort(
                (short) 1
        );

        buffer.putShort(
                (short) 1
        );

        buffer.putInt(
                300
        );

        buffer.putShort(
                (short) 4
        );

        buffer.put(
                new byte[] {
                        (byte) 192, 0, 2, 1
                }
        );

        return slice(buffer);
    }

    private byte[] createCompressedARecordPacket() {

        ByteBuffer buffer =
                ByteBuffer.allocate(512);

        writeHeader(
                buffer,
                0x1234,
                0x8180,
                1,
                1,
                0,
                0
        );

        writeName(
                buffer,
                "example.com"
        );

        buffer.putShort(
                (short) 1
        );

        buffer.putShort(
                (short) 1
        );

        buffer.put(
                (byte) 3
        );

        buffer.put(
                (byte) 'w'
        );

        buffer.put(
                (byte) 'w'
        );

        buffer.put(
                (byte) 'w'
        );

        buffer.put(
                (byte) 0xC0
        );

        buffer.put(
                (byte) 0x0C
        );

        buffer.putShort(
                (short) 1
        );

        buffer.putShort(
                (short) 1
        );

        buffer.putInt(
                300
        );

        buffer.putShort(
                (short) 4
        );

        buffer.put(
                new byte[] {
                        1, 2, 3, 4
                }
        );

        return slice(buffer);
    }

    private void writeHeader(
            ByteBuffer buffer,
            int id,
            int flags,
            int qdCount,
            int anCount,
            int nsCount,
            int arCount
    ) {

        buffer.putShort(
                (short) id
        );

        buffer.putShort(
                (short) flags
        );

        buffer.putShort(
                (short) qdCount
        );

        buffer.putShort(
                (short) anCount
        );

        buffer.putShort(
                (short) nsCount
        );

        buffer.putShort(
                (short) arCount
        );
    }

    private void writeName(
            ByteBuffer buffer,
            String name
    ) {

        DnsNameCodec.encode(
                name,
                buffer
        );
    }

    private byte[] encodeName(
            String name
    ) {

        ByteBuffer buffer =
                ByteBuffer.allocate(255);

        DnsNameCodec.encode(
                name,
                buffer
        );

        return slice(buffer);
    }

    private byte[] slice(
            ByteBuffer buffer
    ) {

        byte[] result =
                new byte[buffer.position()];

        buffer.flip();

        buffer.get(result);

        return result;
    }
}