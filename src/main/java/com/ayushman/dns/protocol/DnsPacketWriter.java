package com.ayushman.dns.protocol;


import java.nio.ByteBuffer;
import java.util.List;

public class DnsPacketWriter {

    public static byte[] buildResponse(DnsMessage response) {

        ByteBuffer buffer = ByteBuffer.allocate(512);

        writeHeader(buffer, response.header());
        writeQuestions(buffer, response.questions());
        writeAnswers(buffer, response.answers());

        return slice(buffer);
    }

    private static void writeHeader(ByteBuffer buffer, DnsHeader header) {
        buffer.putShort((short) header.id());
        buffer.putShort((short) header.flags());
        buffer.putShort((short) header.qdCount());
        buffer.putShort((short) header.anCount());
        buffer.putShort((short) header.nsCount());
        buffer.putShort((short) header.arCount());
    }

    private static void writeQuestions(ByteBuffer buffer, List<DnsQuestion> questions) {
        for (DnsQuestion q : questions) {
            DnsNameCodec.encode(q.name(), buffer);
            buffer.putShort((short) q.type());
            buffer.putShort((short) q.qclass());
        }
    }

    private static void writeAnswers(ByteBuffer buffer, List<DnsRecord> answers) {
        for (DnsRecord record : answers) {
            DnsNameCodec.encode(record.name(), buffer);
            buffer.putShort((short) record.type());
            buffer.putShort((short) record.qclass());
            buffer.putInt(record.ttl());
            buffer.putShort((short) record.rdata().length);
            buffer.put(record.rdata());
        }
    }

    private static byte[] slice(ByteBuffer buffer) {
        byte[] result = new byte[buffer.position()];
        buffer.flip();
        buffer.get(result);
        return result;
    }
}
