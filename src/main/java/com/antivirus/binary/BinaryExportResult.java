package com.antivirus.binary;

/**
 * Результат сборки бинарного пакета: две части, которые далее упаковываются в
 * {@code multipart/mixed} ответ.
 */
public record BinaryExportResult(byte[] manifest, byte[] data) {
}
