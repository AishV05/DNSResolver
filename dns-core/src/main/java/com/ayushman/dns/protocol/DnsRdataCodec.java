package com.ayushman.dns.protocol;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Normalizes the RDATA of records whose fields contain DNS names.
 *
 * <p>Compression pointers are relative to the complete DNS packet, not the
 * RDATA slice. The returned representation therefore expands every supported
 * name and can be written into a different packet without borrowing offsets
 * from the packet that was parsed.</p>
 */
public final class DnsRdataCodec {

    private static final int TYPE_A = 1;
    private static final int TYPE_NS = 2;
    private static final int TYPE_MD = 3;
    private static final int TYPE_MF = 4;
    private static final int TYPE_CNAME = 5;
    private static final int TYPE_SOA = 6;
    private static final int TYPE_MB = 7;
    private static final int TYPE_MG = 8;
    private static final int TYPE_MR = 9;
    private static final int TYPE_PTR = 12;
    private static final int TYPE_MINFO = 14;
    private static final int TYPE_MX = 15;
    private static final int TYPE_RP = 17;
    private static final int TYPE_AFSDB = 18;
    private static final int TYPE_RT = 21;
    private static final int TYPE_SIG = 24;
    private static final int TYPE_PX = 26;
    private static final int TYPE_AAAA = 28;
    private static final int TYPE_NXT = 30;
    private static final int TYPE_SRV = 33;
    private static final int TYPE_NAPTR = 35;
    private static final int TYPE_KX = 36;
    private static final int TYPE_A6 = 38;
    private static final int TYPE_DNAME = 39;

    private static final int MAX_NAME_WIRE_LENGTH = 255;
    private static final int SOA_INTEGER_COUNT = 5;
    private static final int SOA_INTEGER_BYTES = SOA_INTEGER_COUNT * 4;
    private static final int SIG_FIXED_FIELD_BYTES = 18;
    private static final int NXT_MINIMUM_BITMAP_BYTES = 4;

    private DnsRdataCodec() {
    }

    /**
     * Decodes name-bearing RDATA and returns a compression-independent copy.
     * Unknown record types are copied unchanged and marked unsafe for resolver
     * decisions that depend on embedded names.
     */
    public static NormalizedRdata normalize(
            int recordType,
            byte[] packet,
            int rdataOffset,
            int rdLength
    ) {

        validateSlice(recordType, packet, rdataOffset, rdLength);

        int rdataEnd = rdataOffset + rdLength;

        return switch (recordType) {
            case TYPE_A -> normalizeFixedLength(
                    packet,
                    rdataOffset,
                    rdataEnd,
                    4,
                    "A"
            );
            case TYPE_AAAA -> normalizeFixedLength(
                    packet,
                    rdataOffset,
                    rdataEnd,
                    16,
                    "AAAA"
            );
            case TYPE_NS, TYPE_MD, TYPE_MF, TYPE_CNAME, TYPE_MB, TYPE_MG,
                    TYPE_MR, TYPE_PTR, TYPE_DNAME ->
                    normalizeSingleName(packet, rdataOffset, rdataEnd);
            case TYPE_MINFO, TYPE_RP ->
                    normalizeTwoNames(packet, rdataOffset, rdataEnd);
            case TYPE_MX ->
                    normalizePrefixedName(
                            packet,
                            rdataOffset,
                            rdataEnd,
                            2,
                            "MX preference"
                    );
            case TYPE_AFSDB ->
                    normalizePrefixedName(
                            packet,
                            rdataOffset,
                            rdataEnd,
                            2,
                            "AFSDB subtype"
                    );
            case TYPE_RT ->
                    normalizePrefixedName(
                            packet,
                            rdataOffset,
                            rdataEnd,
                            2,
                            "RT preference"
                    );
            case TYPE_KX ->
                    normalizePrefixedName(
                            packet,
                            rdataOffset,
                            rdataEnd,
                            2,
                            "KX preference"
                    );
            case TYPE_PX ->
                    normalizePrefixedTwoNames(
                            packet,
                            rdataOffset,
                            rdataEnd,
                            2,
                            "PX preference"
                    );
            case TYPE_SOA ->
                    normalizeSoa(packet, rdataOffset, rdataEnd);
            case TYPE_SRV ->
                    normalizeSrv(packet, rdataOffset, rdataEnd);
            case TYPE_NAPTR ->
                    normalizeNaptr(packet, rdataOffset, rdataEnd);
            case TYPE_A6 ->
                    normalizeA6(packet, rdataOffset, rdataEnd);
            case TYPE_SIG ->
                    normalizeNameWithOpaqueSuffix(
                            packet,
                            rdataOffset,
                            rdataEnd,
                            SIG_FIXED_FIELD_BYTES,
                            0,
                            "SIG fixed fields"
                    );
            case TYPE_NXT ->
                    normalizeNameWithOpaqueSuffix(
                            packet,
                            rdataOffset,
                            rdataEnd,
                            0,
                            NXT_MINIMUM_BITMAP_BYTES,
                            "NXT type bitmap"
                    );
            default -> NormalizedRdata.opaque(
                    Arrays.copyOfRange(packet, rdataOffset, rdataEnd)
            );
        };
    }

    public static boolean normalizesNameData(int recordType) {
        return recordType == TYPE_NS
                || recordType == TYPE_MD
                || recordType == TYPE_MF
                || recordType == TYPE_CNAME
                || recordType == TYPE_SOA
                || recordType == TYPE_MB
                || recordType == TYPE_MG
                || recordType == TYPE_MR
                || recordType == TYPE_PTR
                || recordType == TYPE_MINFO
                || recordType == TYPE_MX
                || recordType == TYPE_RP
                || recordType == TYPE_AFSDB
                || recordType == TYPE_RT
                || recordType == TYPE_SIG
                || recordType == TYPE_PX
                || recordType == TYPE_NXT
                || recordType == TYPE_SRV
                || recordType == TYPE_NAPTR
                || recordType == TYPE_KX
                || recordType == TYPE_A6
                || recordType == TYPE_DNAME;
    }

    private static NormalizedRdata normalizeFixedLength(
            byte[] packet,
            int rdataOffset,
            int rdataEnd,
            int requiredLength,
            String recordName
    ) {
        int actualLength = rdataEnd - rdataOffset;

        if (actualLength != requiredLength) {
            throw malformed(
                    recordName + " RDATA must contain exactly "
                            + requiredLength + " bytes, not " + actualLength
            );
        }

        return NormalizedRdata.validated(
                Arrays.copyOfRange(packet, rdataOffset, rdataEnd)
        );
    }

    private static NormalizedRdata normalizeSingleName(
            byte[] packet,
            int rdataOffset,
            int rdataEnd
    ) {

        ByteReader reader = readerAt(packet, rdataOffset);
        byte[] name = decodeUncompressedName(reader, packet, rdataEnd);
        requireFullyConsumed(reader.position(), rdataEnd);

        return NormalizedRdata.nameData(name);
    }

    private static NormalizedRdata normalizeTwoNames(
            byte[] packet,
            int rdataOffset,
            int rdataEnd
    ) {

        ByteReader reader = readerAt(packet, rdataOffset);
        byte[] firstName = decodeUncompressedName(reader, packet, rdataEnd);
        byte[] secondName = decodeUncompressedName(reader, packet, rdataEnd);
        requireFullyConsumed(reader.position(), rdataEnd);

        return concatenateNameData(firstName, secondName);
    }

    private static NormalizedRdata normalizePrefixedName(
            byte[] packet,
            int rdataOffset,
            int rdataEnd,
            int prefixLength,
            String prefixDescription
    ) {

        requireRemaining(
                rdataOffset,
                rdataEnd,
                prefixLength,
                prefixDescription
        );

        ByteReader reader = readerAt(packet, rdataOffset);
        byte[] prefix = reader.readBytes(prefixLength);
        byte[] name = decodeUncompressedName(reader, packet, rdataEnd);
        requireFullyConsumed(reader.position(), rdataEnd);

        return concatenateNameData(prefix, name);
    }

    private static NormalizedRdata normalizePrefixedTwoNames(
            byte[] packet,
            int rdataOffset,
            int rdataEnd,
            int prefixLength,
            String prefixDescription
    ) {

        requireRemaining(
                rdataOffset,
                rdataEnd,
                prefixLength,
                prefixDescription
        );

        ByteReader reader = readerAt(packet, rdataOffset);
        byte[] prefix = reader.readBytes(prefixLength);
        byte[] firstName = decodeUncompressedName(reader, packet, rdataEnd);
        byte[] secondName = decodeUncompressedName(reader, packet, rdataEnd);
        requireFullyConsumed(reader.position(), rdataEnd);

        return concatenateNameData(prefix, firstName, secondName);
    }

    private static NormalizedRdata normalizeNaptr(
            byte[] packet,
            int rdataOffset,
            int rdataEnd
    ) {

        requireRemaining(
                rdataOffset,
                rdataEnd,
                4,
                "NAPTR order and preference"
        );

        ByteReader reader = readerAt(packet, rdataOffset);
        reader.readBytes(4);
        skipCharacterString(reader, rdataEnd, "NAPTR flags");
        skipCharacterString(reader, rdataEnd, "NAPTR services");
        skipCharacterString(reader, rdataEnd, "NAPTR regexp");

        int replacementOffset = reader.position();
        byte[] replacement = decodeUncompressedName(reader, packet, rdataEnd);
        requireFullyConsumed(reader.position(), rdataEnd);

        byte[] prefix = Arrays.copyOfRange(
                packet,
                rdataOffset,
                replacementOffset
        );

        return concatenateNameData(prefix, replacement);
    }

    private static void skipCharacterString(
            ByteReader reader,
            int rdataEnd,
            String field
    ) {
        requireRemaining(reader.position(), rdataEnd, 1, field + " length");
        int length = reader.readU8();
        requireRemaining(reader.position(), rdataEnd, length, field);
        reader.readBytes(length);
    }

    private static NormalizedRdata normalizeA6(
            byte[] packet,
            int rdataOffset,
            int rdataEnd
    ) {

        requireRemaining(rdataOffset, rdataEnd, 1, "A6 prefix length");

        ByteReader reader = readerAt(packet, rdataOffset);
        int prefixLength = reader.readU8();
        if (prefixLength > 128) {
            throw malformed("A6 prefix length exceeds 128 bits");
        }

        int suffixLength = (128 - prefixLength + 7) / 8;
        requireRemaining(
                reader.position(),
                rdataEnd,
                suffixLength,
                "A6 address suffix"
        );

        byte[] prefixAndSuffix = Arrays.copyOfRange(
                packet,
                rdataOffset,
                reader.position() + suffixLength
        );
        reader.readBytes(suffixLength);

        if (prefixLength == 0) {
            requireFullyConsumed(reader.position(), rdataEnd);
            return NormalizedRdata.validated(prefixAndSuffix);
        }

        byte[] prefixName = decodeUncompressedName(reader, packet, rdataEnd);
        requireFullyConsumed(reader.position(), rdataEnd);
        return concatenateNameData(prefixAndSuffix, prefixName);
    }

    private static NormalizedRdata normalizeNameWithOpaqueSuffix(
            byte[] packet,
            int rdataOffset,
            int rdataEnd,
            int prefixLength,
            int minimumSuffixLength,
            String fieldDescription
    ) {

        requireRemaining(
                rdataOffset,
                rdataEnd,
                prefixLength,
                fieldDescription
        );

        ByteReader reader = readerAt(packet, rdataOffset);
        byte[] prefix = reader.readBytes(prefixLength);
        byte[] name = decodeUncompressedName(reader, packet, rdataEnd);

        requireRemaining(
                reader.position(),
                rdataEnd,
                minimumSuffixLength,
                fieldDescription
        );
        byte[] suffix = reader.readBytes(rdataEnd - reader.position());
        requireFullyConsumed(reader.position(), rdataEnd);

        return concatenateNameData(prefix, name, suffix);
    }

    private static NormalizedRdata normalizeSoa(
            byte[] packet,
            int rdataOffset,
            int rdataEnd
    ) {

        ByteReader reader = readerAt(packet, rdataOffset);
        byte[] primaryName = decodeUncompressedName(reader, packet, rdataEnd);
        byte[] responsibleMailbox = decodeUncompressedName(
                reader,
                packet,
                rdataEnd
        );

        int integerBytes = rdataEnd - reader.position();

        if (integerBytes < SOA_INTEGER_BYTES) {
            throw malformed("SOA integer fields are truncated");
        }
        if (integerBytes > SOA_INTEGER_BYTES) {
            throw malformed("SOA RDATA has trailing data");
        }

        ByteBuffer normalized = ByteBuffer.allocate(
                primaryName.length
                        + responsibleMailbox.length
                        + SOA_INTEGER_BYTES
        );

        normalized.put(primaryName);
        normalized.put(responsibleMailbox);

        for (int i = 0; i < SOA_INTEGER_COUNT; i++) {
            normalized.putInt((int) reader.readU32());
        }

        requireFullyConsumed(reader.position(), rdataEnd);

        return NormalizedRdata.nameData(normalized.array());
    }

    private static NormalizedRdata normalizeSrv(
            byte[] packet,
            int rdataOffset,
            int rdataEnd
    ) {
        requireRemaining(
                rdataOffset,
                rdataEnd,
                6,
                "SRV priority, weight, and port"
        );

        ByteReader reader = readerAt(packet, rdataOffset);
        byte[] numericFields = reader.readBytes(6);
        byte[] target = decodeUncompressedName(reader, packet, rdataEnd);
        requireFullyConsumed(reader.position(), rdataEnd);

        ByteBuffer normalized = ByteBuffer.allocate(
                numericFields.length + target.length
        );
        normalized.put(numericFields);
        normalized.put(target);

        return NormalizedRdata.nameData(normalized.array());
    }

    private static ByteReader readerAt(byte[] packet, int position) {
        ByteReader reader = new ByteReader(packet);
        reader.position(position);
        return reader;
    }

    private static NormalizedRdata concatenateNameData(byte[]... fields) {
        int length = 0;

        for (byte[] field : fields) {
            if (field.length > 0xFFFF - length) {
                throw malformed("normalized RDATA exceeds 65535 bytes");
            }
            length += field.length;
        }

        ByteBuffer normalized = ByteBuffer.allocate(length);
        for (byte[] field : fields) {
            normalized.put(field);
        }
        return NormalizedRdata.nameData(normalized.array());
    }

    private static byte[] decodeUncompressedName(
            ByteReader reader,
            byte[] packet,
            int rdataEnd
    ) {

        requireRemaining(
                reader.position(),
                rdataEnd,
                1,
                "embedded DNS name"
        );

        String decoded = DnsNameCodec.decode(reader, packet);

        if (reader.position() > rdataEnd) {
            throw malformed("DNS name extends beyond RDLENGTH");
        }

        ByteBuffer encoded = ByteBuffer.allocate(MAX_NAME_WIRE_LENGTH);

        try {
            DnsNameCodec.encode(decoded, encoded);
        } catch (RuntimeException e) {
            throw new DnsFormatException(
                    "Malformed DNS RDATA: decoded name cannot be normalized",
                    e
            );
        }

        return Arrays.copyOf(encoded.array(), encoded.position());
    }

    private static void validateSlice(
            int recordType,
            byte[] packet,
            int rdataOffset,
            int rdLength
    ) {

        if (recordType < 0 || recordType > 0xFFFF) {
            throw new DnsFormatException("DNS record type must fit in 16 bits");
        }

        if (packet == null) {
            throw new DnsFormatException("DNS packet must not be null");
        }

        if (rdataOffset < 0
                || rdLength < 0
                || rdataOffset > packet.length
                || rdLength > packet.length - rdataOffset) {
            throw malformed("RDATA extends outside packet");
        }
    }

    private static void requireFullyConsumed(int position, int end) {
        if (position != end) {
            throw malformed("name-bearing RDATA has trailing data");
        }
    }

    private static void requireRemaining(
            int position,
            int limit,
            int required,
            String field
    ) {

        if (position < 0
                || position > limit
                || required < 0
                || required > limit - position) {
            throw malformed(field + " is truncated");
        }
    }

    private static DnsFormatException malformed(String message) {
        return new DnsFormatException("Malformed DNS RDATA: " + message);
    }

    public static final class NormalizedRdata {

        private final byte[] wireData;
        private final boolean resolverControlSafe;

        private NormalizedRdata(
                byte[] wireData,
                boolean resolverControlSafe
        ) {
            this.wireData = wireData.clone();
            this.resolverControlSafe = resolverControlSafe;
        }

        private static NormalizedRdata nameData(byte[] wireData) {
            return new NormalizedRdata(wireData, true);
        }

        private static NormalizedRdata validated(byte[] wireData) {
            return new NormalizedRdata(wireData, true);
        }

        private static NormalizedRdata opaque(byte[] wireData) {
            return new NormalizedRdata(wireData, false);
        }

        public byte[] wireData() {
            return wireData.clone();
        }

        /**
         * True only when every embedded domain name is understood, validated,
         * and represented without compression pointers.
         */
        public boolean resolverControlSafe() {
            return resolverControlSafe;
        }
    }
}
