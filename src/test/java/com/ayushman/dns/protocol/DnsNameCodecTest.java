package com.ayushman.dns.protocol;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;

public class DnsNameCodecTest {

    @Test
    void shouldDecodeSimpleName() {
        byte[] packet = new byte[] {
            3, 'w','w','w',
            5, 'y','a','h','o','o',
            3, 'c','o','m',
            0
        };

        ByteReader reader = new ByteReader(packet);

        String name = DnsNameCodec.decode(reader, packet);

        assertEquals("www.yahoo.com", name);
    }
}
