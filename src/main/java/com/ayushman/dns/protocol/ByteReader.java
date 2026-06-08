package com.ayushman.dns.protocol;

public class ByteReader {

    private final byte[] data;
    private int pos;

    public ByteReader(byte[] data) {
        this.data = data;
        this.pos = 0;
    }

    public int readU8() {
        return data[pos++] & 0xFF;
    }

    public int readU16() {
        return (readU8() << 8) | readU8();
    }

    public long readU32() {
        return ((long) readU16() << 16) | readU16();
    }

    public int position() {
        return pos;
    }

    public void position(int pos) {
        this.pos = pos;
    }
}