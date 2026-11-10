package com.ayushman.dns.protocol;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.InetAddress;

import org.junit.jupiter.api.Test;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.CNAMERecord;
import org.xbill.DNS.DClass;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Name;
import org.xbill.DNS.Section;
import org.xbill.DNS.Type;

/** Independent wire-format compatibility checks against dnsjava. */
class DnsjavaInteroperabilityTest {

    @Test
    void parsesDnsjavaQueryAndDnsjavaParsesNormalizedQuery() throws Exception {
        Name owner = Name.fromString("www.example.test.");
        org.xbill.DNS.Record question = org.xbill.DNS.Record.newRecord(
                owner,
                Type.A,
                DClass.IN
        );
        org.xbill.DNS.Message external = org.xbill.DNS.Message.newQuery(
                question
        );
        external.getHeader().setID(0x18F0);

        DnsMessage parsed = DnsPacketParser.parse(external.toWire());

        assertEquals(0x18F0, parsed.header().id());
        assertEquals(1, parsed.questions().size());
        assertEquals("www.example.test", parsed.questions().get(0).name());
        assertEquals(Type.A, parsed.questions().get(0).type());

        org.xbill.DNS.Message reparsed = new org.xbill.DNS.Message(
                DnsPacketWriter.buildQuery(parsed)
        );
        assertEquals(0x18F0, reparsed.getHeader().getID());
        assertEquals(1, reparsed.getHeader().getCount(Section.QUESTION));
        assertEquals(owner, reparsed.getQuestion().getName());
        assertEquals(Type.A, reparsed.getQuestion().getType());
    }

    @Test
    void normalizesCompressedCnameResponseForDnsjava() throws Exception {
        Name alias = Name.fromString("alias.example.test.");
        Name target = Name.fromString("target.example.test.");
        org.xbill.DNS.Record question = org.xbill.DNS.Record.newRecord(
                alias,
                Type.A,
                DClass.IN
        );

        org.xbill.DNS.Message external = new org.xbill.DNS.Message(0x18F1);
        external.getHeader().setFlag(Flags.QR);
        external.getHeader().setFlag(Flags.AA);
        external.addRecord(question, Section.QUESTION);
        external.addRecord(
                new CNAMERecord(alias, DClass.IN, 300, target),
                Section.ANSWER
        );
        external.addRecord(
                new ARecord(
                        target,
                        DClass.IN,
                        120,
                        InetAddress.getByName("192.0.2.80")
                ),
                Section.ANSWER
        );

        byte[] compressed = external.toWire();
        DnsMessage parsed = DnsPacketParser.parse(compressed);

        assertEquals(2, parsed.answers().size());
        assertEquals(5, parsed.answers().get(0).type());
        assertTrue(parsed.answers().get(0).rdata().length > 2);

        org.xbill.DNS.Message reparsed = new org.xbill.DNS.Message(
                DnsPacketWriter.buildResponse(parsed)
        );
        assertEquals(0x18F1, reparsed.getHeader().getID());
        assertTrue(reparsed.getHeader().getFlag(Flags.QR));
        assertTrue(reparsed.getHeader().getFlag(Flags.AA));
        assertEquals(2, reparsed.getHeader().getCount(Section.ANSWER));
        assertEquals(alias, reparsed.getQuestion().getName());
    }
}
