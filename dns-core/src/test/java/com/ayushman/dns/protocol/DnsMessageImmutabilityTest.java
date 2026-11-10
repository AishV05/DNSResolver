package com.ayushman.dns.protocol;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

class DnsMessageImmutabilityTest {

    @Test
    void copiesSectionListsAndExposesUnmodifiableViews() {
        DnsQuestion originalQuestion = new DnsQuestion("example.com", 1, 1);
        List<DnsQuestion> questions = new ArrayList<>(List.of(originalQuestion));

        DnsMessage message = new DnsMessage(
                new DnsHeader(1, 0x0100, 1, 0, 0, 0),
                questions,
                List.of(),
                List.of(),
                List.of()
        );

        questions.clear();

        assertEquals(List.of(originalQuestion), message.questions());
        assertThrows(
                UnsupportedOperationException.class,
                () -> message.questions().clear()
        );
    }

    @Test
    void rejectsNullMessageParts() {
        DnsHeader header = new DnsHeader(1, 0, 0, 0, 0, 0);

        assertThrows(
                NullPointerException.class,
                () -> new DnsMessage(null, List.of(), List.of(), List.of(), List.of())
        );
        assertThrows(
                NullPointerException.class,
                () -> new DnsMessage(header, null, List.of(), List.of(), List.of())
        );
    }
}
