package com.ayushman.dns.protocol;

import java.nio.ByteBuffer;
import java.util.List;

public class DnsPacketWriter {

    private static final int MAX_DNS_MESSAGE_SIZE = 65_535;

    public static byte[] buildQuery(DnsMessage query) {
        return buildMessage(query);
    }

    public static byte[] buildResponse(DnsMessage response) {
        return buildMessage(response);
    }

    private static byte[] buildMessage(
            DnsMessage message
    ) {

        ByteBuffer buffer =
                ByteBuffer.allocate(MAX_DNS_MESSAGE_SIZE);

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
                message.answers()
        );

        writeRecords(
                buffer,
                message.authorities()
        );

        writeRecords(
                buffer,
                message.additionals()
        );

        message.edns().ifPresent(
                edns -> writeEdns(buffer, edns)
        );

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
            List<DnsRecord> records
    ) {

        for (DnsRecord record : records) {

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
                    (short) record.rdata().length
            );

            buffer.put(
                    record.rdata()
            );
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
}
