package com.antivirus.binary;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * Тестовый bytes-парсер с курсором, симметричный {@link BinaryWriter}.
 *
 * <p>Используется в тестах для round-trip разбора манифеста и data.bin.</p>
 */
public final class BinaryReader {

    private final byte[] bytes;
    private int position;

    public BinaryReader(byte[] bytes) {
        this.bytes = bytes;
        this.position = 0;
    }

    public int readU8() {
        require(1);
        return bytes[position++] & 0xFF;
    }

    public int readU16BE() {
        require(2);
        int hi = bytes[position++] & 0xFF;
        int lo = bytes[position++] & 0xFF;
        return (hi << 8) | lo;
    }

    public long readU32BE() {
        require(4);
        long b0 = bytes[position++] & 0xFFL;
        long b1 = bytes[position++] & 0xFFL;
        long b2 = bytes[position++] & 0xFFL;
        long b3 = bytes[position++] & 0xFFL;
        return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
    }

    public long readI64BE() {
        require(8);
        long result = 0L;
        for (int i = 0; i < 8; i++) {
            result = (result << 8) | (bytes[position++] & 0xFFL);
        }
        return result;
    }

    public UUID readUuid() {
        long msb = readI64BE();
        long lsb = readI64BE();
        return new UUID(msb, lsb);
    }

    public String readUtf8WithU16Length() {
        int length = readU16BE();
        require(length);
        String s = new String(bytes, position, length, StandardCharsets.UTF_8);
        position += length;
        return s;
    }

    public byte[] readBytesWithU16Length() {
        int length = readU16BE();
        return readBytesRaw(length);
    }

    public byte[] readBytesWithU32Length() {
        int length = (int) readU32BE();
        return readBytesRaw(length);
    }

    public byte[] readBytesRaw(int length) {
        require(length);
        byte[] out = new byte[length];
        System.arraycopy(bytes, position, out, 0, length);
        position += length;
        return out;
    }

    public int position() {
        return position;
    }

    public int remaining() {
        return bytes.length - position;
    }

    private void require(int n) {
        if (position + n > bytes.length) {
            throw new IllegalStateException("Not enough bytes: need " + n + ", have " + (bytes.length - position));
        }
    }
}
