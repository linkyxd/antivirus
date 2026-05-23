package com.antivirus.binary;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * Низкоуровневая утилита бинарной сериализации.
 *
 * <p>Все многобайтовые числа пишутся в порядке <b>BigEndian</b> (network byte order).
 * Это совпадает с поведением {@link java.io.DataOutputStream} и упрощает разбор на
 * любой клиентской платформе.</p>
 *
 * <p>Все побитовые сдвиги и маски сосредоточены в этом классе: остальные части модуля
 * оперируют доменными терминами ({@code uint16 length + bytes} и т. д.), не задумываясь
 * о порядке байт.</p>
 *
 * <p>Длины строк и массивов:</p>
 * <ul>
 *     <li>{@code uint16} — для коротких полей (имена, hex-данные);</li>
 *     <li>{@code uint32} — для длинных массивов (подписи).</li>
 * </ul>
 */
public final class BinaryWriter {

    private final ByteArrayOutputStream out;

    public BinaryWriter() {
        this.out = new ByteArrayOutputStream();
    }

    public BinaryWriter(ByteArrayOutputStream out) {
        this.out = out;
    }

    public BinaryWriter writeU8(int value) {
        out.write(value & 0xFF);
        return this;
    }

    public BinaryWriter writeU16BE(int value) {
        out.write((value >>> 8) & 0xFF);
        out.write(value & 0xFF);
        return this;
    }

    public BinaryWriter writeU32BE(long value) {
        out.write((int) ((value >>> 24) & 0xFF));
        out.write((int) ((value >>> 16) & 0xFF));
        out.write((int) ((value >>> 8) & 0xFF));
        out.write((int) (value & 0xFF));
        return this;
    }

    public BinaryWriter writeI64BE(long value) {
        out.write((int) ((value >>> 56) & 0xFF));
        out.write((int) ((value >>> 48) & 0xFF));
        out.write((int) ((value >>> 40) & 0xFF));
        out.write((int) ((value >>> 32) & 0xFF));
        out.write((int) ((value >>> 24) & 0xFF));
        out.write((int) ((value >>> 16) & 0xFF));
        out.write((int) ((value >>> 8) & 0xFF));
        out.write((int) (value & 0xFF));
        return this;
    }

    /** {@code uint64} BigEndian. Hardware-wise совпадает с {@link #writeI64BE(long)}. */
    public BinaryWriter writeU64BE(long value) {
        return writeI64BE(value);
    }

    /**
     * UUID кодируется как 16 сырых байт: msb (8 байт BigEndian) + lsb (8 байт BigEndian).
     * Ровно как делает {@code UUID.getMostSignificantBits/getLeastSignificantBits}.
     */
    public BinaryWriter writeUuid(UUID uuid) {
        writeI64BE(uuid.getMostSignificantBits());
        writeI64BE(uuid.getLeastSignificantBits());
        return this;
    }

    /** {@code uint16 length + bytes (UTF-8)}. */
    public BinaryWriter writeUtf8WithU16Length(String value) {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        if (bytes.length > 0xFFFF) {
            throw new IllegalArgumentException("UTF-8 string too long for uint16 length: " + bytes.length);
        }
        writeU16BE(bytes.length);
        writeRaw(bytes);
        return this;
    }

    /** {@code uint16 length + bytes}. */
    public BinaryWriter writeBytesWithU16Length(byte[] bytes) {
        if (bytes.length > 0xFFFF) {
            throw new IllegalArgumentException("Byte array too long for uint16 length: " + bytes.length);
        }
        writeU16BE(bytes.length);
        writeRaw(bytes);
        return this;
    }

    /** {@code uint32 length + bytes}. */
    public BinaryWriter writeBytesWithU32Length(byte[] bytes) {
        writeU32BE(bytes.length);
        writeRaw(bytes);
        return this;
    }

    /** Записывает массив байт как есть, без префикса длины. */
    public BinaryWriter writeRaw(byte[] bytes) {
        try {
            out.write(bytes);
        } catch (IOException e) {
            // ByteArrayOutputStream никогда не бросает IOException,
            // оборачиваем для защиты на случай подмены потока.
            throw new IllegalStateException("Unexpected IO error in BinaryWriter", e);
        }
        return this;
    }

    public byte[] toByteArray() {
        return out.toByteArray();
    }

    public int size() {
        return out.size();
    }
}
