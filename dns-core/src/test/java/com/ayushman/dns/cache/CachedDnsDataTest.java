package com.ayushman.dns.cache;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.ayushman.dns.protocol.DnsQuestion;

class CachedDnsDataTest {

    @Test
    void defensivelyCopiesSectionLists() {
        DnsQuestion question = new DnsQuestion("example.com", 1, 1);
        List<DnsQuestion> questions = new ArrayList<>(List.of(question));

        CachedDnsData data = new CachedDnsData(
                questions,
                List.of(),
                List.of(),
                List.of()
        );

        questions.clear();

        assertEquals(List.of(question), data.questions());
        assertThrows(
                UnsupportedOperationException.class,
                () -> data.questions().clear()
        );
    }
}
