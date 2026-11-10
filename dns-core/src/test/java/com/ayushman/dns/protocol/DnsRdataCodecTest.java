package com.ayushman.dns.protocol;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class DnsRdataCodecTest {

    private static final byte[] EXAMPLE_COM = name("example", "com");
    private static final byte[] WWW_EXAMPLE_COM = name(
            "www",
            "example",
            "com"
    );

    @ParameterizedTest
    @ValueSource(ints = {2, 5, 12, 39})
    void roundTripsUncompressedSingleNameTypes(int recordType) {

        DnsRdataCodec.NormalizedRdata normalized =
                DnsRdataCodec.normalize(
                        recordType,
                        WWW_EXAMPLE_COM,
                        0,
                        WWW_EXAMPLE_COM.length
                );

        assertArrayEquals(
                WWW_EXAMPLE_COM,
                normalized.wireData()
        );
        assertTrue(normalized.resolverControlSafe());

        assertArrayEquals(
                WWW_EXAMPLE_COM,
                DnsRdataCodec.normalize(
                        recordType,
                        normalized.wireData(),
                        0,
                        normalized.wireData().length
                ).wireData()
        );
    }

    @ParameterizedTest
    @ValueSource(ints = {2, 5, 12, 39})
    void expandsCompressedSingleNameTypes(int recordType) {

        byte[] compressedRdata = concat(
                new byte[] {3, 'w', 'w', 'w'},
                pointer(0)
        );
        byte[] packet = concat(EXAMPLE_COM, compressedRdata);

        DnsRdataCodec.NormalizedRdata normalized =
                DnsRdataCodec.normalize(
                        recordType,
                        packet,
                        EXAMPLE_COM.length,
                        compressedRdata.length
                );

        assertArrayEquals(
                WWW_EXAMPLE_COM,
                normalized.wireData()
        );
        assertTrue(normalized.resolverControlSafe());
    }

    @Test
    void expandsMxExchangeAndPreservesPreference() {

        byte[] compressedRdata = concat(
                new byte[] {0, 10, 4, 'm', 'a', 'i', 'l'},
                pointer(0)
        );
        byte[] packet = concat(EXAMPLE_COM, compressedRdata);
        byte[] expected = concat(
                new byte[] {0, 10},
                name("mail", "example", "com")
        );

        DnsRdataCodec.NormalizedRdata normalized =
                DnsRdataCodec.normalize(
                        15,
                        packet,
                        EXAMPLE_COM.length,
                        compressedRdata.length
                );

        assertArrayEquals(expected, normalized.wireData());
        assertTrue(normalized.resolverControlSafe());
        assertArrayEquals(
                expected,
                DnsRdataCodec.normalize(
                        15,
                        expected,
                        0,
                        expected.length
                ).wireData()
        );
    }

    @Test
    void expandsSoaNamesAndPreservesAllIntegers() {

        byte[] integers = ByteBuffer.allocate(20)
                .putInt(0x01020304)
                .putInt(7200)
                .putInt(3600)
                .putInt(1_209_600)
                .putInt(300)
                .array();

        byte[] compressedRdata = concat(
                new byte[] {2, 'n', 's'},
                pointer(0),
                new byte[] {
                        10, 'h', 'o', 's', 't', 'm', 'a', 's', 't', 'e', 'r'
                },
                pointer(0),
                integers
        );
        byte[] packet = concat(EXAMPLE_COM, compressedRdata);
        byte[] expected = concat(
                name("ns", "example", "com"),
                name("hostmaster", "example", "com"),
                integers
        );

        DnsRdataCodec.NormalizedRdata normalized =
                DnsRdataCodec.normalize(
                        6,
                        packet,
                        EXAMPLE_COM.length,
                        compressedRdata.length
                );

        assertArrayEquals(expected, normalized.wireData());
        assertTrue(normalized.resolverControlSafe());
        assertArrayEquals(
                expected,
                DnsRdataCodec.normalize(
                        6,
                        expected,
                        0,
                        expected.length
                ).wireData()
        );
    }

    @Test
    void rejectsTrailingBytesInNameBearingRdata() {

        byte[] nameWithTrailingByte = concat(
                EXAMPLE_COM,
                new byte[] {42}
        );

        assertThrows(
                DnsFormatException.class,
                () -> DnsRdataCodec.normalize(
                        2,
                        nameWithTrailingByte,
                        0,
                        nameWithTrailingByte.length
                )
        );

        byte[] mxWithTrailingByte = concat(
                new byte[] {0, 10},
                EXAMPLE_COM,
                new byte[] {42}
        );

        assertThrows(
                DnsFormatException.class,
                () -> DnsRdataCodec.normalize(
                        15,
                        mxWithTrailingByte,
                        0,
                        mxWithTrailingByte.length
                )
        );
    }

    @Test
    void rejectsMalformedSoaFields() {

        byte[] tooFewIntegers = concat(
                EXAMPLE_COM,
                EXAMPLE_COM,
                new byte[19]
        );
        byte[] trailingData = concat(
                EXAMPLE_COM,
                EXAMPLE_COM,
                new byte[21]
        );

        assertThrows(
                DnsFormatException.class,
                () -> DnsRdataCodec.normalize(
                        6,
                        tooFewIntegers,
                        0,
                        tooFewIntegers.length
                )
        );
        assertThrows(
                DnsFormatException.class,
                () -> DnsRdataCodec.normalize(
                        6,
                        trailingData,
                        0,
                        trailingData.length
                )
        );
    }

    @Test
    void rejectsPointersThatEscapeRdataOrCycle() {

        byte[] truncatedPointer = new byte[] {(byte) 0xC0};
        byte[] cyclicPointer = pointer(0);

        assertThrows(
                DnsFormatException.class,
                () -> DnsRdataCodec.normalize(
                        2,
                        truncatedPointer,
                        0,
                        truncatedPointer.length
                )
        );
        assertThrows(
                DnsFormatException.class,
                () -> DnsRdataCodec.normalize(
                        2,
                        cyclicPointer,
                        0,
                        cyclicPointer.length
                )
        );
    }

    @Test
    void rejectsRdataSliceOutsidePacket() {

        assertThrows(
                DnsFormatException.class,
                () -> DnsRdataCodec.normalize(
                        2,
                        EXAMPLE_COM,
                        EXAMPLE_COM.length - 1,
                        2
                )
        );
    }

    @Test
    void keepsUnknownTypesOpaqueAndDefensivelyCopied() {

        byte[] packet = new byte[] {10, 20, 30, 40};

        DnsRdataCodec.NormalizedRdata normalized =
                DnsRdataCodec.normalize(65_000, packet, 1, 2);

        packet[1] = 99;

        assertArrayEquals(
                new byte[] {20, 30},
                normalized.wireData()
        );
        assertFalse(normalized.resolverControlSafe());

        byte[] exposedCopy = normalized.wireData();
        exposedCopy[0] = 88;

        assertArrayEquals(
                new byte[] {20, 30},
                normalized.wireData()
        );
    }

    @Test
    void reportsOnlyImplementedNameTypesAsNormalized() {
        assertTrue(DnsRdataCodec.normalizesNameData(2));
        assertTrue(DnsRdataCodec.normalizesNameData(5));
        assertTrue(DnsRdataCodec.normalizesNameData(6));
        assertTrue(DnsRdataCodec.normalizesNameData(12));
        assertTrue(DnsRdataCodec.normalizesNameData(15));
        assertTrue(DnsRdataCodec.normalizesNameData(33));
        assertTrue(DnsRdataCodec.normalizesNameData(39));
        assertFalse(DnsRdataCodec.normalizesNameData(1));
        assertFalse(DnsRdataCodec.normalizesNameData(28));
        assertFalse(DnsRdataCodec.normalizesNameData(65_000));
    }

    private static byte[] name(String... labels) {

        ByteArrayOutputStream wire = new ByteArrayOutputStream();

        for (String label : labels) {
            byte[] bytes = label.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
            wire.write(bytes.length);
            wire.writeBytes(bytes);
        }

        wire.write(0);
        return wire.toByteArray();
    }

    private static byte[] pointer(int offset) {
        return new byte[] {
                (byte) (0xC0 | ((offset >>> 8) & 0x3F)),
                (byte) offset
        };
    }

    private static byte[] concat(byte[]... parts) {

        ByteArrayOutputStream result = new ByteArrayOutputStream();

        for (byte[] part : parts) {
            result.writeBytes(part);
        }

        return result.toByteArray();
    }
}
