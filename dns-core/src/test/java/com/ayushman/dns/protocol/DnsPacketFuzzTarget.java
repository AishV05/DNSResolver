package com.ayushman.dns.protocol;

/** Standalone Jazzer entry point for the untrusted DNS wire boundary. */
public final class DnsPacketFuzzTarget {

    private DnsPacketFuzzTarget() {
    }

    public static void fuzzerTestOneInput(byte[] wire) {
        if (wire == null || wire.length > 65_535) {
            return;
        }

        DnsMessage parsed;
        try {
            parsed = DnsPacketParser.parse(wire);
        } catch (DnsFormatException expectedRejection) {
            return;
        }

        byte[] normalized = DnsPacketWriter.buildResponse(parsed);
        DnsMessage reparsed = DnsPacketParser.parse(normalized);

        requireEqual(parsed.header().id(), reparsed.header().id(), "ID");
        requireEqual(
                parsed.header().flags(),
                reparsed.header().flags(),
                "flags"
        );
        requireEqual(
                parsed.questions().size(),
                reparsed.questions().size(),
                "question count"
        );
        requireEqual(
                parsed.answers().size(),
                reparsed.answers().size(),
                "answer count"
        );
        requireEqual(
                parsed.authorities().size(),
                reparsed.authorities().size(),
                "authority count"
        );
        requireEqual(
                parsed.additionals().size(),
                reparsed.additionals().size(),
                "additional count"
        );
        requireEqual(
                parsed.edns().isPresent() ? 1 : 0,
                reparsed.edns().isPresent() ? 1 : 0,
                "EDNS presence"
        );
    }

    private static void requireEqual(
            int expected,
            int actual,
            String field
    ) {
        if (expected != actual) {
            throw new AssertionError(
                    "DNS packet round-trip changed " + field
                            + " from " + expected + " to " + actual
            );
        }
    }
}
