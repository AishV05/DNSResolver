package com.ayushman.dns.protocol;

public final class EdnsInfo {

    public static final int OPT_RECORD_TYPE = 41;

    public static final int VERSION_ZERO = 0;

    public static final int DNSSEC_OK_FLAG = 0x8000;

    private final int udpPayloadSize;

    private final int extendedRcode;

    private final int version;

    private final int flags;

    private final byte[] options;

    public EdnsInfo(
            int udpPayloadSize,
            int extendedRcode,
            int version,
            int flags,
            byte[] options
    ) {

        validateUnsigned16(
                udpPayloadSize,
                "udpPayloadSize"
        );

        validateUnsigned8(
                extendedRcode,
                "extendedRcode"
        );

        validateUnsigned8(
                version,
                "version"
        );

        validateUnsigned16(flags, "flags");

        if (options == null) {
            throw new IllegalArgumentException(
                    "options must not be null"
            );
        }

        if (options.length > 0xFFFF) {
            throw new IllegalArgumentException(
                    "options must not exceed 65535 bytes"
            );
        }

        this.udpPayloadSize = udpPayloadSize;
        this.extendedRcode = extendedRcode;
        this.version = version;
        this.flags = flags;
        this.options = options.clone();
    }

    public static EdnsInfo fromOptRecord(
            DnsRecord record
    ) {

        if (record.type() != OPT_RECORD_TYPE) {
            throw new IllegalArgumentException(
                    "EDNS data must come from an OPT record"
            );
        }

        if (!record.name().isEmpty()) {
            throw new IllegalArgumentException(
                    "OPT record name must be the root domain"
            );
        }

        long ttl = record.ttl();

        int extendedRcode =
                (int) ((ttl >>> 24) & 0xFF);

        int version =
                (int) ((ttl >>> 16) & 0xFF);

        int flags =
                (int) (ttl & 0xFFFF);

        return new EdnsInfo(
                record.qclass(),
                extendedRcode,
                version,
                flags,
                record.rdata()
        );
    }

    public int udpPayloadSize() {
        return udpPayloadSize;
    }

    public int effectiveUdpPayloadSize() {
        return Math.max(512, udpPayloadSize);
    }

    public int extendedRcode() {
        return extendedRcode;
    }

    public int version() {
        return version;
    }

    public int flags() {
        return flags;
    }

    public boolean dnssecOk() {
        return (flags & DNSSEC_OK_FLAG) != 0;
    }

    public byte[] options() {
        return options.clone();
    }

    public long ttl() {
        return ((long) extendedRcode << 24)
                | ((long) version << 16)
                | flags;
    }

    private static void validateUnsigned8(
            int value,
            String name
    ) {

        if (value < 0 || value > 0xFF) {
            throw new IllegalArgumentException(
                    name + " must be an unsigned 8-bit value"
            );
        }
    }

    private static void validateUnsigned16(
            int value,
            String name
    ) {

        if (value < 0 || value > 0xFFFF) {
            throw new IllegalArgumentException(
                    name + " must be an unsigned 16-bit value"
            );
        }
    }
}
