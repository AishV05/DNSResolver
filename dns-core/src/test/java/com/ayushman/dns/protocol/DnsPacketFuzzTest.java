package com.ayushman.dns.protocol;

import java.util.stream.Stream;

import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.ParameterizedTest;

/** Coverage-guided and regression-corpus checks for the DNS wire boundary. */
class DnsPacketFuzzTest {

    @ParameterizedTest
    @MethodSource("seedPackets")
    void fuzzDnsPacket(byte[] wire) {
        DnsPacketFuzzTarget.fuzzerTestOneInput(wire);
    }

    static Stream<Arguments> seedPackets() {
        Stream<Arguments> malformed = AdversarialDnsPacketCorpus.all().stream()
                .map(fixture -> Arguments.of((Object) fixture.wireBytes()));
        return Stream.concat(
                Stream.of(
                        Arguments.of((Object) new byte[0]),
                        Arguments.of((Object) new byte[12]),
                        Arguments.of((Object) TestPackets.GOOGLE_QUERY.clone())
                ),
                malformed
        );
    }
}
