package com.ayushman.dns.protocol;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

class EdnsInfoValidationTest {

    @Test
    void acceptsExactlyFramedOptions() {
        byte[] options = {
                0, 10, 0, 2, 1, 2,
                0, 11, 0, 0
        };

        EdnsInfo edns = new EdnsInfo(1_232, 0, 0, 0, options);

        assertArrayEquals(options, edns.options());
    }

    @Test
    void rejectsTruncatedOptionHeader() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new EdnsInfo(1_232, 0, 0, 0, new byte[] {0, 10, 0})
        );
    }

    @Test
    void rejectsTruncatedOptionData() {
        assertThrows(
                IllegalArgumentException.class,
                () -> new EdnsInfo(
                        1_232,
                        0,
                        0,
                        0,
                        new byte[] {0, 10, 0, 2, 1}
                )
        );
    }
}
