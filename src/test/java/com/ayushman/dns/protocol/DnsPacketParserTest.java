package com.ayushman.dns.protocol;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;

public class DnsPacketParserTest {

    @Test
    void shouldParseHeaderCorrectly() {
        DnsMessage message = DnsPacketParser.parse(TestPackets.GOOGLE_QUERY);

        DnsHeader header = message.header();

        assertEquals(0x1234, header.id());
        assertEquals(1, header.qdCount());
        assertEquals(0, header.anCount());
        assertEquals(0, header.nsCount());
        assertEquals(0, header.arCount());
    }

    @Test
    void shouldParseQuestionCorrectly() {
        DnsMessage message = DnsPacketParser.parse(TestPackets.GOOGLE_QUERY);

        assertEquals(1, message.questions().size());

        DnsQuestion question = message.questions().get(0);

        assertEquals("google.com", question.name());
        assertEquals(1, question.type());   // A record
        assertEquals(1, question.qclass()); // IN
    }
}
