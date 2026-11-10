package com.ayushman.dns.protocol;

import java.io.ByteArrayOutputStream;
import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;
import java.nio.ReadOnlyBufferException;
import java.util.ArrayList;
import java.util.List;

public final class DnsNameCodec {

    private static final int MAX_LABEL_LENGTH = 63;
    private static final int MAX_EXPANDED_NAME_LENGTH = 255;
    private static final int MAX_COMPRESSION_POINTERS = 32;

    private DnsNameCodec() {
    }

    public static String decode(
            ByteReader reader,
            byte[] packet
    ) {
        requireMatchingInput(reader, packet);

        StringBuilder name = new StringBuilder();
        int returnPosition = -1;
        int pointerCount = 0;
        int expandedLength = 1;

        while (true) {
            int labelOffset = reader.position();
            int length = reader.readU8();
            int labelForm = length & 0xC0;

            if (labelForm == 0xC0) {
                int pointerLowBits = reader.readU8();
                int pointerTarget = ((length & 0x3F) << 8) | pointerLowBits;

                pointerCount++;
                if (pointerCount > MAX_COMPRESSION_POINTERS) {
                    throw new DnsFormatException(
                            "DNS name exceeds the compression pointer limit of "
                                    + MAX_COMPRESSION_POINTERS
                    );
                }
                if (pointerTarget >= packet.length) {
                    throw new DnsFormatException(
                            "DNS compression pointer target " + pointerTarget
                                    + " is outside packet length " + packet.length
                    );
                }
                if (pointerTarget >= labelOffset) {
                    throw new DnsFormatException(
                            "DNS compression pointer at offset " + labelOffset
                                    + " must target a prior offset, not " + pointerTarget
                    );
                }

                if (returnPosition < 0) {
                    returnPosition = reader.position();
                }
                reader.position(pointerTarget);
                continue;
            }

            if (labelForm != 0) {
                throw new DnsFormatException(
                        "Reserved DNS label form at offset " + labelOffset
                );
            }
            if (length == 0) {
                break;
            }
            if (length > MAX_LABEL_LENGTH) {
                throw new DnsFormatException(
                        "DNS label exceeds " + MAX_LABEL_LENGTH + " octets"
                );
            }

            expandedLength += length + 1;
            if (expandedLength > MAX_EXPANDED_NAME_LENGTH) {
                throw new DnsFormatException(
                        "Expanded DNS name exceeds "
                                + MAX_EXPANDED_NAME_LENGTH + " octets"
                );
            }

            if (name.length() > 0) {
                name.append('.');
            }
            for (int i = 0; i < length; i++) {
                appendEscapedOctet(name, reader.readU8());
            }
        }

        if (returnPosition >= 0) {
            reader.position(returnPosition);
        }
        return name.toString();
    }

    private static void appendEscapedOctet(
            StringBuilder name,
            int octet
    ) {
        if (octet >= 0x21 && octet <= 0x7E) {
            if (octet == '.' || octet == '\\') {
                name.append('\\');
            }
            name.append((char) octet);
            return;
        }

        name.append('\\');
        name.append((char) ('0' + (octet / 100)));
        name.append((char) ('0' + ((octet / 10) % 10)));
        name.append((char) ('0' + (octet % 10)));
    }

    private static void requireMatchingInput(
            ByteReader reader,
            byte[] packet
    ) {
        if (reader == null) {
            throw new DnsFormatException("DNS byte reader must not be null");
        }
        if (packet == null) {
            throw new DnsFormatException("DNS packet must not be null");
        }
        if (!reader.isBackedBy(packet)) {
            throw new DnsFormatException(
                    "DNS byte reader and packet must share the same backing data"
            );
        }
    }

    public static void encode(
            String name,
            ByteBuffer buffer
    ) {
        if (name == null) {
            throw new IllegalArgumentException("DNS name must not be null");
        }
        if (buffer == null) {
            throw new NullPointerException("DNS output buffer must not be null");
        }

        EncodedName encodedName = parsePresentation(name);

        if (buffer.isReadOnly()) {
            throw new ReadOnlyBufferException();
        }
        if (buffer.remaining() < encodedName.wireLength()) {
            throw new BufferOverflowException();
        }

        for (byte[] label : encodedName.labels()) {
            buffer.put((byte) label.length);
            buffer.put(label);
        }
        buffer.put((byte) 0);
    }

    private static EncodedName parsePresentation(String name) {
        if (name.isEmpty() || name.equals(".")) {
            return new EncodedName(List.of(), 1);
        }

        List<byte[]> labels = new ArrayList<>();
        ByteArrayOutputStream label = new ByteArrayOutputStream();
        boolean terminalDot = false;

        for (int index = 0; index < name.length();) {
            char value = name.charAt(index);

            if (value == '.') {
                if (label.size() == 0) {
                    throw invalidName("DNS name contains an empty label");
                }
                labels.add(label.toByteArray());
                label.reset();
                terminalDot = index == name.length() - 1;
                index++;
                continue;
            }

            int octet;
            if (value == '\\') {
                Escape escape = parseEscape(name, index);
                octet = escape.octet();
                index = escape.nextIndex();
            } else {
                if (value < 0x21 || value > 0x7E) {
                    throw invalidName(
                            "DNS name contains an unescaped non-printable or non-ASCII character"
                    );
                }
                octet = value;
                index++;
            }

            label.write(octet);
            if (label.size() > MAX_LABEL_LENGTH) {
                throw invalidName(
                        "DNS label exceeds " + MAX_LABEL_LENGTH + " octets"
                );
            }
        }

        if (!terminalDot) {
            if (label.size() == 0) {
                throw invalidName("DNS name contains an empty label");
            }
            labels.add(label.toByteArray());
        }

        int wireLength = 1;
        for (byte[] encodedLabel : labels) {
            wireLength += encodedLabel.length + 1;
        }
        if (wireLength > MAX_EXPANDED_NAME_LENGTH) {
            throw invalidName(
                    "Encoded DNS name exceeds "
                            + MAX_EXPANDED_NAME_LENGTH + " octets"
            );
        }
        return new EncodedName(List.copyOf(labels), wireLength);
    }

    private static Escape parseEscape(String name, int slashIndex) {
        int escapedIndex = slashIndex + 1;
        if (escapedIndex >= name.length()) {
            throw invalidName("DNS name ends with an incomplete escape");
        }

        char escaped = name.charAt(escapedIndex);
        if (escaped == '.' || escaped == '\\') {
            return new Escape(escaped, escapedIndex + 1);
        }
        if (!isAsciiDigit(escaped)
                || escapedIndex + 2 >= name.length()
                || !isAsciiDigit(name.charAt(escapedIndex + 1))
                || !isAsciiDigit(name.charAt(escapedIndex + 2))) {
            throw invalidName(
                    "DNS escapes must be \\. or \\\\ or exactly three decimal digits"
            );
        }

        int octet = (escaped - '0') * 100
                + (name.charAt(escapedIndex + 1) - '0') * 10
                + name.charAt(escapedIndex + 2) - '0';
        if (octet > 255) {
            throw invalidName("DNS decimal escape exceeds 255");
        }
        return new Escape(octet, escapedIndex + 3);
    }

    private static boolean isAsciiDigit(char value) {
        return value >= '0' && value <= '9';
    }

    private static IllegalArgumentException invalidName(String message) {
        return new IllegalArgumentException(message);
    }

    private record EncodedName(List<byte[]> labels, int wireLength) {
    }

    private record Escape(int octet, int nextIndex) {
    }
}
