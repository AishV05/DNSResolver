package com.ayushman.dns.cache;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.ayushman.dns.protocol.DnsNameCodec;

/** Label-preserving, ASCII-case-insensitive DNS name used in cache keys. */
public final class CanonicalDnsName {

    private static final int MAX_WIRE_NAME_BYTES = 255;
    private final byte[] wireName;

    private CanonicalDnsName(byte[] wireName) {
        this.wireName = wireName;
    }

    public static CanonicalDnsName from(String presentation) {
        ByteBuffer encoded = ByteBuffer.allocate(MAX_WIRE_NAME_BYTES);
        DnsNameCodec.encode(presentation, encoded);
        encoded.flip();

        byte[] canonical = new byte[encoded.remaining()];
        encoded.get(canonical);

        int position = 0;
        while (position < canonical.length) {
            int length = canonical[position] & 0xFF;
            position++;
            if (length == 0) {
                if (position != canonical.length) {
                    throw new IllegalArgumentException(
                            "DNS name contains data after its root label"
                    );
                }
                return new CanonicalDnsName(canonical);
            }
            if (position + length > canonical.length) {
                throw new IllegalArgumentException(
                        "DNS name contains a truncated label"
                );
            }
            for (int index = position; index < position + length; index++) {
                int value = canonical[index] & 0xFF;
                if (value >= 'A' && value <= 'Z') {
                    canonical[index] = (byte) (value + ('a' - 'A'));
                }
            }
            position += length;
        }

        throw new IllegalArgumentException("DNS name has no root label");
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof CanonicalDnsName name
                && Arrays.equals(wireName, name.wireName);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(wireName);
    }

    public boolean isAtOrBelow(CanonicalDnsName zone) {
        if (zone == null) {
            throw new IllegalArgumentException("zone must not be null");
        }
        List<byte[]> nameLabels = labels();
        List<byte[]> zoneLabels = zone.labels();
        if (zoneLabels.size() > nameLabels.size()) {
            return false;
        }
        int offset = nameLabels.size() - zoneLabels.size();
        for (int index = 0; index < zoneLabels.size(); index++) {
            if (!Arrays.equals(
                    nameLabels.get(offset + index),
                    zoneLabels.get(index)
            )) {
                return false;
            }
        }
        return true;
    }

    private List<byte[]> labels() {
        List<byte[]> labels = new ArrayList<>();
        int position = 0;
        while (position < wireName.length) {
            int length = wireName[position] & 0xFF;
            position++;
            if (length == 0) {
                return List.copyOf(labels);
            }
            labels.add(Arrays.copyOfRange(
                    wireName,
                    position,
                    position + length
            ));
            position += length;
        }
        throw new IllegalStateException("canonical DNS name has no root label");
    }
}
