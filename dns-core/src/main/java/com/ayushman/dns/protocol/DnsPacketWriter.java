package com.ayushman.dns.protocol;

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.util.List;
import java.util.Objects;

public final class DnsPacketWriter {

    private static final int MAX_DNS_MESSAGE_SIZE = 65_535;

    private DnsPacketWriter() {
    }

    public static byte[] buildQuery(DnsMessage query) {
        return buildMessage(query);
    }

    public static byte[] buildResponse(DnsMessage response) {
        return buildMessage(response);
    }

    private static byte[] buildMessage(
            DnsMessage message
    ) {

        Objects.requireNonNull(message, "message");

        validateSectionCounts(message);
        validateHeader(message.header());

        ByteBuffer buffer =
                ByteBuffer.allocate(MAX_DNS_MESSAGE_SIZE);

        try {
            writeHeader(
                    buffer,
                    headerForWriting(message)
            );

            writeQuestions(
                    buffer,
                    message.questions()
            );

            writeRecords(
                    buffer,
                    message.answers(),
                    "answer"
            );

            writeRecords(
                    buffer,
                    message.authorities(),
                    "authority"
            );

            writeRecords(
                    buffer,
                    message.additionals(),
                    "additional"
            );

            message.edns().ifPresent(
                    edns -> writeEdns(buffer, edns)
            );
        } catch (BufferOverflowException e) {
            throw new IllegalArgumentException(
                    "Encoded DNS message exceeds 65535 bytes",
                    e
            );
        }

        return slice(buffer);
    }

    private static DnsHeader headerForWriting(
            DnsMessage message
    ) {

        int additionalCount =
                message.additionals().size()
                        + (message.edns().isPresent() ? 1 : 0);

        return new DnsHeader(
                message.header().id(),
                message.header().flags(),
                message.questions().size(),
                message.answers().size(),
                message.authorities().size(),
                additionalCount
        );
    }

    private static void writeHeader(
            ByteBuffer buffer,
            DnsHeader header
    ) {
        buffer.putShort((short) header.id());
        buffer.putShort((short) header.flags());
        buffer.putShort((short) header.qdCount());
        buffer.putShort((short) header.anCount());
        buffer.putShort((short) header.nsCount());
        buffer.putShort((short) header.arCount());
    }

    private static void writeQuestions(
            ByteBuffer buffer,
            List<DnsQuestion> questions
    ) {

        for (DnsQuestion q : questions) {

            Objects.requireNonNull(q, "question");
            requireUnsigned16(q.type(), "question type");
            requireUnsigned16(q.qclass(), "question class");

            if (q.type() == EdnsInfo.OPT_RECORD_TYPE) {
                throw new IllegalArgumentException(
                        "OPT is a pseudo-record and cannot be written as a question"
                );
            }

            DnsNameCodec.encode(
                    q.name(),
                    buffer
            );

            buffer.putShort(
                    (short) q.type()
            );

            buffer.putShort(
                    (short) q.qclass()
            );
        }
    }

    private static void writeRecords(
            ByteBuffer buffer,
            List<DnsRecord> records,
            String section
    ) {

        for (DnsRecord record : records) {

            Objects.requireNonNull(record, section + " record");
            requireUnsigned16(record.type(), section + " record type");
            requireUnsigned16(record.qclass(), section + " record class");
            requireUnsigned32(record.ttl(), section + " record TTL");

            if (record.type() == EdnsInfo.OPT_RECORD_TYPE) {
                throw new IllegalArgumentException(
                        "OPT records must be represented by DnsMessage.edns(), not the "
                                + section + " record list"
                );
            }

            byte[] sourceRdata = record.rdata();
            requireUnsigned16Count(
                    sourceRdata.length,
                    section + " record RDATA length"
            );
            byte[] normalizedRdata = DnsRdataCodec.normalize(
                    record.type(),
                    sourceRdata,
                    0,
                    sourceRdata.length
            ).wireData();
            requireUnsigned16Count(
                    normalizedRdata.length,
                    section + " normalized RDATA length"
            );

            DnsNameCodec.encode(
                    record.name(),
                    buffer
            );

            buffer.putShort(
                    (short) record.type()
            );

            buffer.putShort(
                    (short) record.qclass()
            );

            // DNS TTL = 4 bytes
            buffer.putInt(
                    (int) record.ttl()
            );

            buffer.putShort(
                    (short) normalizedRdata.length
            );

            buffer.put(normalizedRdata);
        }
    }

    private static void writeEdns(
            ByteBuffer buffer,
            EdnsInfo edns
    ) {

        buffer.put((byte) 0);
        buffer.putShort((short) EdnsInfo.OPT_RECORD_TYPE);
        buffer.putShort((short) edns.udpPayloadSize());
        buffer.putInt((int) edns.ttl());

        byte[] options = edns.options();

        buffer.putShort((short) options.length);
        buffer.put(options);
    }

    private static byte[] slice(
            ByteBuffer buffer
    ) {

        byte[] result =
                new byte[buffer.position()];

        buffer.flip();

        buffer.get(result);

        return result;
    }

    private static void validateSectionCounts(DnsMessage message) {
        requireUnsigned16Count(message.questions().size(), "question");
        requireUnsigned16Count(message.answers().size(), "answer");
        requireUnsigned16Count(message.authorities().size(), "authority");

        long additionalCount = (long) message.additionals().size()
                + (message.edns().isPresent() ? 1L : 0L);
        requireUnsigned16Count(additionalCount, "additional");
    }

    private static void validateHeader(DnsHeader header) {
        Objects.requireNonNull(header, "header");
        requireUnsigned16(header.id(), "header ID");
        requireUnsigned16(header.flags(), "header flags");
    }

    private static void requireUnsigned16(int value, String field) {
        if (value < 0 || value > 0xFFFF) {
            throw new IllegalArgumentException(
                    field + " must be an unsigned 16-bit value"
            );
        }
    }

    private static void requireUnsigned32(long value, String field) {
        if (value < 0 || value > 0xFFFF_FFFFL) {
            throw new IllegalArgumentException(
                    field + " must be an unsigned 32-bit value"
            );
        }
    }

    private static void requireUnsigned16Count(long count, String section) {
        if (count > 0xFFFFL) {
            throw new IllegalArgumentException(
                    "DNS " + section + " count exceeds 65535"
            );
        }
    }
}
