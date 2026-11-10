package com.ayushman.dns.protocol;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

class DnsRdataCodecLegacyTypesTest {

    private static final byte[] EXAMPLE_COM = name("example", "com");

    @ParameterizedTest
    @ValueSource(ints = {3, 4, 7, 8, 9})
    void expandsRfc1035SingleNameRdata(int recordType) {
        byte[] packet = concat(EXAMPLE_COM, pointer(0));

        DnsRdataCodec.NormalizedRdata normalized =
                DnsRdataCodec.normalize(
                        recordType,
                        packet,
                        EXAMPLE_COM.length,
                        2
                );

        assertArrayEquals(EXAMPLE_COM, normalized.wireData());
        assertTrue(normalized.resolverControlSafe());
        assertTrue(DnsRdataCodec.normalizesNameData(recordType));
    }

    @ParameterizedTest
    @ValueSource(ints = {14, 17})
    void expandsTwoNameRdata(int recordType) {
        byte[] firstCompressed = concat(
                new byte[] {4, 'l', 'i', 's', 't'},
                pointer(0)
        );
        byte[] secondCompressed = concat(
                new byte[] {6, 'e', 'r', 'r', 'o', 'r', 's'},
                pointer(0)
        );
        byte[] rdata = concat(firstCompressed, secondCompressed);
        byte[] packet = concat(EXAMPLE_COM, rdata);

        DnsRdataCodec.NormalizedRdata normalized =
                DnsRdataCodec.normalize(
                        recordType,
                        packet,
                        EXAMPLE_COM.length,
                        rdata.length
                );

        assertArrayEquals(
                concat(
                        name("list", "example", "com"),
                        name("errors", "example", "com")
                ),
                normalized.wireData()
        );
        assertTrue(normalized.resolverControlSafe());
    }

    @ParameterizedTest
    @ValueSource(ints = {18, 21, 36})
    void preservesTwoBytePrefixAndExpandsFollowingName(int recordType) {
        byte[] prefix = new byte[] {0x12, 0x34};
        byte[] compressedName = concat(
                new byte[] {4, 'm', 'a', 'i', 'l'},
                pointer(0)
        );
        byte[] rdata = concat(prefix, compressedName);
        byte[] packet = concat(EXAMPLE_COM, rdata);

        DnsRdataCodec.NormalizedRdata normalized =
                DnsRdataCodec.normalize(
                        recordType,
                        packet,
                        EXAMPLE_COM.length,
                        rdata.length
                );

        assertArrayEquals(
                concat(prefix, name("mail", "example", "com")),
                normalized.wireData()
        );
        assertTrue(normalized.resolverControlSafe());
    }

    @Test
    void preservesPxPreferenceAndExpandsBothMappingNames() {
        byte[] preference = new byte[] {0, 25};
        byte[] map822 = concat(
                new byte[] {6, 'r', 'f', 'c', '8', '2', '2'},
                pointer(0)
        );
        byte[] mapX400 = concat(
                new byte[] {4, 'x', '4', '0', '0'},
                pointer(0)
        );
        byte[] rdata = concat(preference, map822, mapX400);
        byte[] packet = concat(EXAMPLE_COM, rdata);

        DnsRdataCodec.NormalizedRdata normalized =
                DnsRdataCodec.normalize(
                        26,
                        packet,
                        EXAMPLE_COM.length,
                        rdata.length
                );

        assertArrayEquals(
                concat(
                        preference,
                        name("rfc822", "example", "com"),
                        name("x400", "example", "com")
                ),
                normalized.wireData()
        );
        assertTrue(normalized.resolverControlSafe());
    }

    @Test
    void preservesNaptrScalarsAndCharacterStringsAndExpandsReplacement() {
        byte[] prefix = new byte[] {
                0, 10,
                0, 20,
                1, 'S',
                7, 'S', 'I', 'P', '+', 'D', '2', 'U',
                0
        };
        byte[] compressedReplacement = concat(
                new byte[] {4, 's', 'i', 'p', 's'},
                pointer(0)
        );
        byte[] rdata = concat(prefix, compressedReplacement);
        byte[] packet = concat(EXAMPLE_COM, rdata);

        DnsRdataCodec.NormalizedRdata normalized =
                DnsRdataCodec.normalize(
                        35,
                        packet,
                        EXAMPLE_COM.length,
                        rdata.length
                );

        assertArrayEquals(
                concat(prefix, name("sips", "example", "com")),
                normalized.wireData()
        );
        assertTrue(normalized.resolverControlSafe());
    }

    @Test
    void preservesSigFixedFieldsAndSignatureAndExpandsSignerName() {
        byte[] fixedFields = new byte[18];
        for (int index = 0; index < fixedFields.length; index++) {
            fixedFields[index] = (byte) (index + 1);
        }
        byte[] signature = new byte[] {0, (byte) 0xFF, 0x55};
        byte[] rdata = concat(fixedFields, pointer(0), signature);
        byte[] packet = concat(EXAMPLE_COM, rdata);

        DnsRdataCodec.NormalizedRdata normalized =
                DnsRdataCodec.normalize(
                        24,
                        packet,
                        EXAMPLE_COM.length,
                        rdata.length
                );

        assertArrayEquals(
                concat(fixedFields, EXAMPLE_COM, signature),
                normalized.wireData()
        );
        assertTrue(normalized.resolverControlSafe());
    }

    @Test
    void preservesNxtBitmapAndExpandsNextDomainName() {
        byte[] bitmap = new byte[] {0, 0, 0, 2};
        byte[] rdata = concat(pointer(0), bitmap);
        byte[] packet = concat(EXAMPLE_COM, rdata);

        DnsRdataCodec.NormalizedRdata normalized =
                DnsRdataCodec.normalize(
                        30,
                        packet,
                        EXAMPLE_COM.length,
                        rdata.length
                );

        assertArrayEquals(
                concat(EXAMPLE_COM, bitmap),
                normalized.wireData()
        );
        assertTrue(normalized.resolverControlSafe());
    }

    @Test
    void validatesA6SuffixAndExpandsOptionalPrefixName() {
        byte[] suffix = new byte[] {
                0x12, 0x34, 0x56, 0x78,
                (byte) 0x9A, (byte) 0xBC, (byte) 0xDE, (byte) 0xF0
        };
        byte[] rdata = concat(new byte[] {64}, suffix, pointer(0));
        byte[] packet = concat(EXAMPLE_COM, rdata);

        DnsRdataCodec.NormalizedRdata normalized =
                DnsRdataCodec.normalize(
                        38,
                        packet,
                        EXAMPLE_COM.length,
                        rdata.length
                );

        assertArrayEquals(
                concat(new byte[] {64}, suffix, EXAMPLE_COM),
                normalized.wireData()
        );
        assertTrue(normalized.resolverControlSafe());
        assertTrue(DnsRdataCodec.normalizesNameData(38));

        byte[] completeAddress = concat(new byte[] {0}, new byte[16]);
        assertArrayEquals(
                completeAddress,
                DnsRdataCodec.normalize(
                        38,
                        completeAddress,
                        0,
                        completeAddress.length
                ).wireData()
        );

        byte[] prefixOnly = concat(new byte[] {(byte) 128}, EXAMPLE_COM);
        assertArrayEquals(
                prefixOnly,
                DnsRdataCodec.normalize(
                        38,
                        prefixOnly,
                        0,
                        prefixOnly.length
                ).wireData()
        );
    }

    @ParameterizedTest
    @ValueSource(ints = {14, 17})
    void rejectsMissingSecondName(int recordType) {
        assertThrows(
                DnsFormatException.class,
                () -> DnsRdataCodec.normalize(
                        recordType,
                        EXAMPLE_COM,
                        0,
                        EXAMPLE_COM.length
                )
        );
    }

    @ParameterizedTest
    @ValueSource(ints = {18, 21, 36})
    void rejectsMissingNameAfterTwoBytePrefix(int recordType) {
        byte[] prefixOnly = new byte[] {0, 10};

        assertThrows(
                DnsFormatException.class,
                () -> DnsRdataCodec.normalize(
                        recordType,
                        prefixOnly,
                        0,
                        prefixOnly.length
                )
        );
    }

    @Test
    void rejectsTruncatedPxNaptrSigAndNxtLayouts() {
        byte[] pxWithOnlyOneName = concat(new byte[] {0, 10}, EXAMPLE_COM);
        byte[] naptrWithTruncatedFlags = new byte[] {
                0, 1, 0, 1, 3, 'S'
        };
        byte[] sigWithoutSignerName = new byte[18];
        byte[] nxtWithShortBitmap = concat(
                EXAMPLE_COM,
                new byte[] {0, 0, 2}
        );

        assertMalformed(26, pxWithOnlyOneName);
        assertMalformed(35, naptrWithTruncatedFlags);
        assertMalformed(24, sigWithoutSignerName);
        assertMalformed(30, nxtWithShortBitmap);
    }

    @Test
    void rejectsInvalidA6Layouts() {
        assertMalformed(38, new byte[] {(byte) 129});
        assertMalformed(38, concat(new byte[] {0}, new byte[15]));
        assertMalformed(38, concat(new byte[] {0}, new byte[16], new byte[] {0}));
        assertMalformed(38, concat(new byte[] {64}, new byte[8]));
    }

    @Test
    void leavesPostRfc3597TypesOpaque() {
        byte[] pointerShapedData = new byte[] {
                1, 2, (byte) 0xC0, 0, 3, 4
        };

        DnsRdataCodec.NormalizedRdata rrsig =
                DnsRdataCodec.normalize(
                        46,
                        pointerShapedData,
                        0,
                        pointerShapedData.length
                );
        DnsRdataCodec.NormalizedRdata svcb =
                DnsRdataCodec.normalize(
                        64,
                        pointerShapedData,
                        0,
                        pointerShapedData.length
                );

        assertArrayEquals(pointerShapedData, rrsig.wireData());
        assertArrayEquals(pointerShapedData, svcb.wireData());
        assertFalse(rrsig.resolverControlSafe());
        assertFalse(svcb.resolverControlSafe());
        assertFalse(DnsRdataCodec.normalizesNameData(46));
        assertFalse(DnsRdataCodec.normalizesNameData(64));
    }

    private static void assertMalformed(int recordType, byte[] rdata) {
        assertThrows(
                DnsFormatException.class,
                () -> DnsRdataCodec.normalize(
                        recordType,
                        rdata,
                        0,
                        rdata.length
                )
        );
    }

    private static byte[] name(String... labels) {
        ByteArrayOutputStream wire = new ByteArrayOutputStream();

        for (String label : labels) {
            byte[] bytes = label.getBytes(StandardCharsets.US_ASCII);
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
