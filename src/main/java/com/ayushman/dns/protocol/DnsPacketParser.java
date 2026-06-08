package com.ayushman.dns.protocol;

import java.util.ArrayList;
import java.util.List;

public class DnsPacketParser {

    public static DnsMessage parse(byte[] packet) {

        ByteReader reader = new ByteReader(packet);

        DnsHeader header = new DnsHeader(
                reader.readU16(),
                reader.readU16(),
                reader.readU16(),
                reader.readU16(),
                reader.readU16(),
                reader.readU16()
        );

        List<DnsQuestion> questions = new ArrayList<>();

        for (int i = 0; i < header.qdCount(); i++) {

            String name = DnsNameCodec.decode(reader, packet);

            int type = reader.readU16();
            int qclass = reader.readU16();

            questions.add(
                    new DnsQuestion(name, type, qclass)
            );
        }

        List<DnsRecord> answers = new ArrayList<>();

        for (int i = 0; i < header.anCount(); i++) {
            answers.add(readRecord(reader, packet));
        }

        List<DnsRecord> authorities = new ArrayList<>();

        for (int i = 0; i < header.nsCount(); i++) {
            authorities.add(readRecord(reader, packet));
        }

        List<DnsRecord> additionals = new ArrayList<>();

        for (int i = 0; i < header.arCount(); i++) {
            additionals.add(readRecord(reader, packet));
        }

        return new DnsMessage(
                header,
                questions,
                answers,
                authorities,
                additionals
        );
    }

    private static DnsRecord readRecord(
        ByteReader reader,
        byte[] packet
) {

        String name = DnsNameCodec.decode(reader, packet);
        int type = reader.readU16();
        int qclass = reader.readU16();

        long ttl = reader.readU32();

        int rdLength = reader.readU16();

        byte[] rdata = new byte[rdLength];

        for (int i = 0; i < rdLength; i++) {
            rdata[i] = (byte) reader.readU8();
        }

        return new DnsRecord(
                name,
                type,
                qclass,
                ttl,
                rdata
        );
    }

    
}