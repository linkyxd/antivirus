package com.antivirus.binary;

import java.util.UUID;

/**
 * Внутренняя структура одной записи в манифесте, до сериализации.
 *
 * <p>Поля повторяют схему из методички (раздел 4.2): UUID, статус, время обновления,
 * диапазон в data.bin и сырые байты подписи записи (декодированные из Base64-поля
 * {@code digitalSignatureBase64}).</p>
 */
public record ManifestEntry(
        UUID id,
        byte statusCode,
        long updatedAtEpochMillis,
        long dataOffset,
        int dataLength,
        byte[] recordSignatureBytes
) {
}
