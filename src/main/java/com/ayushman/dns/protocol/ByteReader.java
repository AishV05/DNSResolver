package com.ayushman.dns.protocol;

public class ByteReader {
    private final byte[] data;
    private int pos = 0;

    public ByteReader(byte[] data) {
        this.data = data;
    }

    public int readU8() {
        return data[pos++] & 0xFF;
    }

    public int readU16() {
        return (readU8() << 8) | readU8();
    }

    public int position() {
        return pos;
    }

    public void position(int newPos) {
        this.pos = newPos;
    }
}
