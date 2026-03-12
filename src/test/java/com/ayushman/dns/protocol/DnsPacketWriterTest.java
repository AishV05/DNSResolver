package com.ayushman.dns.protocol;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;

import com.ayushman.dns.resolver.SimpleResolver;

public class DnsPacketWriterTest {

    @Test
    void shouldBuildValidAResponsePacket() {

        DnsMessage query = DnsPacketParser.parse(TestPackets.GOOGLE_QUERY);

        SimpleResolver resolver = new SimpleResolver();
        DnsMessage responseMessage = resolver.resolve(query);

        byte[] responseBytes = DnsPacketWriter.buildResponse(responseMessage);

       
        assertNotNull(responseBytes);
        assertTrue(responseBytes.length > 20);

        
        DnsMessage parsedResponse = DnsPacketParser.parse(responseBytes);

        assertEquals(query.header().id(), parsedResponse.header().id());
        assertEquals(1, parsedResponse.header().anCount());

        
        assertEquals(query.questions().get(0).name(),
                parsedResponse.questions().get(0).name());

       
        int answerCount =
                ((responseBytes[6] & 0xFF) << 8)
                        | (responseBytes[7] & 0xFF);

        assertEquals(1, answerCount);
    }
}
