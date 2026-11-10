package com.ayushman.dns.protocol;

import java.util.ArrayList;
import java.util.List;

public final class DnsPacketParser {

    private static final int MAX_DNS_MESSAGE_SIZE = 65_535;
    private static final int MIN_QUESTION_SIZE = 5;
    private static final int MIN_RECORD_SIZE = 11;

    private DnsPacketParser() {
    }

    public static DnsMessage parse(byte[] packet) {

        if (packet == null) {
            throw new DnsFormatException("DNS packet must not be null");
        }
        if (packet.length > MAX_DNS_MESSAGE_SIZE) {
            throw new DnsFormatException(
                    "DNS packet exceeds the 65535-byte wire limit"
            );
        }

        ByteReader reader = new ByteReader(packet);

        DnsHeader header = new DnsHeader(
                reader.readU16(),
                reader.readU16(),
                reader.readU16(),
                reader.readU16(),
                reader.readU16(),
                reader.readU16()
        );

        requireDeclaredSectionsCanFit(header, reader.remaining());

        List<DnsQuestion> questions = new ArrayList<>();

        for (int i = 0; i < header.qdCount(); i++) {

            String name = DnsNameCodec.decode(reader, packet);

            int type = reader.readU16();
            int qclass = reader.readU16();

            if (type == EdnsInfo.OPT_RECORD_TYPE) {
                throw new DnsFormatException(
                        "OPT is a pseudo-record and cannot appear in the question section"
                );
            }

            questions.add(
                    new DnsQuestion(name, type, qclass)
            );
        }

        List<DnsRecord> answers = new ArrayList<>();

        for (int i = 0; i < header.anCount(); i++) {
            DnsRecord record = readRecord(reader, packet);
            rejectOptOutsideAdditional(record, "answer");
            answers.add(record);
        }

        List<DnsRecord> authorities = new ArrayList<>();

        for (int i = 0; i < header.nsCount(); i++) {
            DnsRecord record = readRecord(reader, packet);
            rejectOptOutsideAdditional(record, "authority");
            authorities.add(record);
        }

        List<DnsRecord> additionals = new ArrayList<>();

        EdnsInfo edns = null;

        for (int i = 0; i < header.arCount(); i++) {

            DnsRecord record =
                    readRecord(reader, packet);

            if (record.type() == EdnsInfo.OPT_RECORD_TYPE) {

                if (edns != null) {
                    throw new DnsFormatException(
                            "DNS message contains multiple OPT records"
                    );
                }

                try {
                    edns = EdnsInfo.fromOptRecord(record);
                } catch (IllegalArgumentException e) {
                    throw new DnsFormatException(
                            "Malformed OPT record: " + e.getMessage(),
                            e
                    );
                }
            } else {
                additionals.add(record);
            }
        }

        if (reader.remaining() != 0) {
            throw new DnsFormatException(
                    "DNS packet contains " + reader.remaining()
                            + " trailing byte(s) after its declared sections"
            );
        }

        return new DnsMessage(
                header,
                questions,
                answers,
                authorities,
                additionals,
                edns
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
        int rdataOffset = reader.position();

        DnsRdataCodec.NormalizedRdata normalized =
                DnsRdataCodec.normalize(
                        type,
                        packet,
                        rdataOffset,
                        rdLength
                );

        reader.position(rdataOffset + rdLength);

        return new DnsRecord(
                name,
                type,
                qclass,
                ttl,
                normalized.wireData()
        );
    }

    private static void requireDeclaredSectionsCanFit(
            DnsHeader header,
            int remainingBytes
    ) {
        long minimumBytes = (long) header.qdCount() * MIN_QUESTION_SIZE
                + (long) header.anCount() * MIN_RECORD_SIZE
                + (long) header.nsCount() * MIN_RECORD_SIZE
                + (long) header.arCount() * MIN_RECORD_SIZE;

        if (minimumBytes > remainingBytes) {
            throw new DnsFormatException(
                    "DNS section counts require at least " + minimumBytes
                            + " byte(s), but only " + remainingBytes
                            + " remain"
            );
        }
    }

    private static void rejectOptOutsideAdditional(
            DnsRecord record,
            String section
    ) {
        if (record.type() == EdnsInfo.OPT_RECORD_TYPE) {
            throw new DnsFormatException(
                    "OPT records may not appear in the DNS "
                            + section + " section"
            );
        }
    }
}
