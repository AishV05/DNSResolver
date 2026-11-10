package com.ayushman.dns.protocol;

import java.util.Arrays;

public final class ByteReader {

    private final byte[] data;
    private int position;

    public ByteReader(byte[] data) {
        if (data == null) {
            throw new DnsFormatException("DNS wire data must not be null");
        }
        this.data = data;
    }

    public int readU8() {
        requireAvailable(1);
        return data[position++] & 0xFF;
    }

    public int readU16() {
        requireAvailable(2);
        int value = ((data[position] & 0xFF) << 8)
                | (data[position + 1] & 0xFF);
        position += 2;
        return value;
    }

    public long readU32() {
        requireAvailable(4);
        long value = ((long) (data[position] & 0xFF) << 24)
                | ((long) (data[position + 1] & 0xFF) << 16)
                | ((long) (data[position + 2] & 0xFF) << 8)
                | (long) (data[position + 3] & 0xFF);
        position += 4;
        return value;
    }

    public byte[] readBytes(int length) {
        if (length < 0) {
            throw new DnsFormatException("Byte count must not be negative: " + length);
        }
        requireAvailable(length);
        byte[] result = Arrays.copyOfRange(data, position, position + length);
        position += length;
        return result;
    }

    public int position() {
        return position;
    }

    public void position(int newPosition) {
        if (newPosition < 0 || newPosition > data.length) {
            throw new DnsFormatException(
                    "DNS wire position " + newPosition
                            + " is outside packet length " + data.length
            );
        }
        position = newPosition;
    }

    public int remaining() {
        return data.length - position;
    }

    public int length() {
        return data.length;
    }

    boolean isBackedBy(byte[] candidate) {
        return data == candidate;
    }

    private void requireAvailable(int length) {
        if (length > remaining()) {
            throw new DnsFormatException(
                    "DNS wire data is truncated at offset " + position
                            + ": need " + length
                            + " byte(s), have " + remaining()
            );
        }
    }
}
