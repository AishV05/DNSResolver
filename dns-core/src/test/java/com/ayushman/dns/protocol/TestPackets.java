package com.ayushman.dns.protocol;

public class TestPackets {

    // dig google.com A
    public static final byte[] GOOGLE_QUERY = new byte[] {
        (byte)0x12, (byte)0x34, // ID
        (byte)0x01, (byte)0x00, // Flags (standard query)
        (byte)0x00, (byte)0x01, // QDCOUNT = 1
        (byte)0x00, (byte)0x00, // ANCOUNT
        (byte)0x00, (byte)0x00, // NSCOUNT
        (byte)0x00, (byte)0x00, // ARCOUNT

        // QNAME = google.com
        (byte)0x06, 'g','o','o','g','l','e',
        (byte)0x03, 'c','o','m',
        (byte)0x00,

        (byte)0x00, (byte)0x01, // QTYPE = A
        (byte)0x00, (byte)0x01  // QCLASS = IN
    };
}
