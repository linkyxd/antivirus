package com.antivirus.binary;

/**
 * Декодер hex-строк в массив байт.
 *
 * <p>В предметной модели поля {@code firstBytesHex}/{@code remainderHashHex} хранятся как
 * человекочитаемый hex (это удобно для подписи и отладки). При записи в {@code data.bin}
 * они декодируются в сырые байты — это компактнее и удобнее клиенту.</p>
 */
public final class HexCodec {

    private HexCodec() {
    }

    public static byte[] decode(String hex) {
        if (hex == null) {
            throw new IllegalArgumentException("hex string must not be null");
        }
        if ((hex.length() & 1) != 0) {
            throw new IllegalArgumentException("hex string must have even length: " + hex.length());
        }
        byte[] result = new byte[hex.length() / 2];
        for (int i = 0; i < result.length; i++) {
            int hi = Character.digit(hex.charAt(i * 2), 16);
            int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (hi < 0 || lo < 0) {
                throw new IllegalArgumentException("Invalid hex character at index " + (i * 2));
            }
            result[i] = (byte) ((hi << 4) | lo);
        }
        return result;
    }
}
