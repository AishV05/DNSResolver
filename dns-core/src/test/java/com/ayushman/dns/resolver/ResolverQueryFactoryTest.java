package com.ayushman.dns.resolver;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.SecureRandom;

import org.junit.jupiter.api.Test;

import com.ayushman.dns.protocol.DnsMessage;
import com.ayushman.dns.protocol.DnsQuestion;
import com.ayushman.dns.protocol.EdnsInfo;

public class ResolverQueryFactoryTest {

    private static final DnsQuestion QUESTION =
            new DnsQuestion("example.com", 1, 1);

    @Test
    void shouldAddEdnsZeroToUpstreamQuery() {

        DnsMessage query =
                ResolverQueryFactory.create(
                        QUESTION
                );

        EdnsInfo edns = query.edns().orElseThrow();

        assertEquals(
                ResolverQueryFactory.UPSTREAM_UDP_PAYLOAD_SIZE,
                edns.udpPayloadSize()
        );
        assertEquals(0, edns.extendedRcode());
        assertEquals(0, edns.version());
        assertEquals(0, edns.flags());
        assertFalse(edns.dnssecOk());
        assertEquals(0, edns.options().length);
    }

    @Test
    void shouldUseAllSixteenBitsFromInjectedSecureRandom() {
        RecordingSecureRandom random = new RecordingSecureRandom(0xFFFF);

        DnsMessage query = ResolverQueryFactory.create(QUESTION, random);

        assertEquals(0xFFFF, query.header().id());
        assertEquals(ResolverQueryFactory.TRANSACTION_ID_BOUND, random.bound());
        assertEquals(1, random.calls());
    }

    @Test
    void shouldAcceptZeroAsTransactionId() {
        RecordingSecureRandom random = new RecordingSecureRandom(0);

        DnsMessage query = ResolverQueryFactory.create(QUESTION, random);

        assertEquals(0, query.header().id());
    }

    @Test
    void shouldSendIterativeQueriesWithoutRequestingRecursion() {
        DnsMessage query =
                ResolverQueryFactory.create(
                        QUESTION,
                        new RecordingSecureRandom(1)
                );

        assertEquals(0, query.header().flags() & 0x0100);
    }

    @Test
    void shouldRejectAnInvalidTransactionIdFromInjectedSource() {
        RecordingSecureRandom random =
                new RecordingSecureRandom(
                        ResolverQueryFactory.TRANSACTION_ID_BOUND
                );

        assertThrows(
                IllegalStateException.class,
                () -> ResolverQueryFactory.create(QUESTION, random)
        );
    }

    private static final class RecordingSecureRandom extends SecureRandom {

        private final int result;
        private int bound;
        private int calls;

        private RecordingSecureRandom(int result) {
            this.result = result;
        }

        @Override
        public int nextInt(int bound) {
            this.bound = bound;
            calls++;
            return result;
        }

        private int bound() {
            return bound;
        }

        private int calls() {
            return calls;
        }
    }
}
