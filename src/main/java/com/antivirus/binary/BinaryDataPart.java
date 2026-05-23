package com.antivirus.binary;

import java.util.List;

/**
 * Результат сериализации {@code data.bin}.
 *
 * <p>Содержит сами байты файла, его SHA-256 (для манифеста) и список диапазонов
 * (offset/length) каждой записи относительно <b>начала payload-области</b> data.bin
 * (то есть после заголовка). Этот же offset попадает в {@link ManifestEntry}.</p>
 */
public record BinaryDataPart(
        byte[] bytes,
        byte[] sha256,
        List<RecordRange> ranges
) {
    public record RecordRange(long offset, int length) {
    }
}
