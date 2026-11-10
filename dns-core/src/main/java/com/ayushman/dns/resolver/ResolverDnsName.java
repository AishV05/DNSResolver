package com.ayushman.dns.resolver;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import com.ayushman.dns.protocol.DnsNameCodec;

/**
 * Label-aware, ASCII-case-insensitive DNS name used for resolver decisions.
 */
final class ResolverDnsName {

    private static final int MAX_WIRE_NAME_BYTES = 255;

    private final List<String> labels;

    private ResolverDnsName(List<String> labels) {
        this.labels = List.copyOf(labels);
    }

    static ResolverDnsName from(String presentation) {
        ByteBuffer wire = ByteBuffer.allocate(MAX_WIRE_NAME_BYTES);
        DnsNameCodec.encode(presentation, wire);
        wire.flip();

        List<String> labels = new ArrayList<>();

        while (wire.hasRemaining()) {
            int length = wire.get() & 0xFF;

            if (length == 0) {
                if (wire.hasRemaining()) {
                    throw new IllegalArgumentException(
                            "DNS name has bytes after its root label"
                    );
                }
                return new ResolverDnsName(labels);
            }

            byte[] label = new byte[length];
            wire.get(label);

            for (int index = 0; index < label.length; index++) {
                int value = label[index] & 0xFF;
                if (value >= 'A' && value <= 'Z') {
                    label[index] = (byte) (value + ('a' - 'A'));
                }
            }

            labels.add(
                    new String(label, StandardCharsets.ISO_8859_1)
            );
        }

        throw new IllegalArgumentException(
                "DNS name is missing its root label"
        );
    }

    boolean isAtOrBelow(ResolverDnsName zone) {
        if (zone.labels.size() > labels.size()) {
            return false;
        }

        int offset = labels.size() - zone.labels.size();
        for (int index = 0; index < zone.labels.size(); index++) {
            if (!labels.get(offset + index).equals(zone.labels.get(index))) {
                return false;
            }
        }
        return true;
    }

    boolean isStrictlyBelow(ResolverDnsName zone) {
        return labels.size() > zone.labels.size() && isAtOrBelow(zone);
    }

    int labelCount() {
        return labels.size();
    }

    @Override
    public boolean equals(Object other) {
        return other instanceof ResolverDnsName name
                && labels.equals(name.labels);
    }

    @Override
    public int hashCode() {
        return labels.hashCode();
    }

    @Override
    public String toString() {
        return labels.toString();
    }
}
