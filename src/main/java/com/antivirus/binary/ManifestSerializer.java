package com.antivirus.binary;

import com.antivirus.signature.SignatureService;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Сериализатор бинарного манифеста {@code manifest.bin}.
 *
 * <p>Структура (BigEndian):</p>
 * <pre>
 * header:
 *     uint16 magicLength
 *     bytes  magic ("MF-&lt;surname&gt;")
 *     uint16 version
 *     uint8  exportType (0=FULL, 1=INCREMENT, 2=BY_IDS)
 *     int64  generatedAtEpochMillis
 *     int64  sinceEpochMillis    (-1 для FULL/BY_IDS)
 *     uint32 recordCount
 *     bytes  dataSha256          (32 байта без префикса длины)
 *
 * entries (recordCount раз):
 *     bytes(16) uuid              (msb int64 BE + lsb int64 BE)
 *     uint8     statusCode
 *     int64     updatedAtEpochMillis
 *     uint64    dataOffset
 *     uint32    dataLength
 *     uint32    recordSignatureLength
 *     bytes     recordSignatureBytes
 *
 * trailer:
 *     uint32 manifestSignatureLength
 *     bytes  manifestSignatureBytes
 * </pre>
 *
 * <p>Подпись манифеста считается по неподписанной части (header + entries) через
 * {@link SignatureService#signBytes(byte[])}. После этого длина и байты подписи
 * дописываются в конец потока.</p>
 */
@Component
public class ManifestSerializer {

    private final BinaryProtocolProperties properties;
    private final SignatureService signatureService;

    public ManifestSerializer(BinaryProtocolProperties properties, SignatureService signatureService) {
        this.properties = properties;
        this.signatureService = signatureService;
    }

    public byte[] serialize(ManifestSerializationInput input) {
        if (input.dataSha256().length != 32) {
            throw new IllegalArgumentException("dataSha256 must be 32 bytes, got " + input.dataSha256().length);
        }

        BinaryWriter writer = new BinaryWriter();

        // header
        writer.writeUtf8WithU16Length(properties.manifestMagic());
        writer.writeU16BE(properties.getManifestVersion());
        writer.writeU8(input.exportType().code());
        writer.writeI64BE(input.generatedAtEpochMillis());
        writer.writeI64BE(input.sinceEpochMillis());
        writer.writeU32BE(input.entries().size());
        writer.writeRaw(input.dataSha256());

        // entries
        for (ManifestEntry entry : input.entries()) {
            writer.writeUuid(entry.id());
            writer.writeU8(entry.statusCode());
            writer.writeI64BE(entry.updatedAtEpochMillis());
            writer.writeU64BE(entry.dataOffset());
            writer.writeU32BE(entry.dataLength());
            writer.writeBytesWithU32Length(entry.recordSignatureBytes());
        }

        byte[] unsigned = writer.toByteArray();
        byte[] manifestSignature = signatureService.signBytes(unsigned);

        // trailer
        writer.writeBytesWithU32Length(manifestSignature);
        return writer.toByteArray();
    }

    public record ManifestSerializationInput(
            ExportType exportType,
            long generatedAtEpochMillis,
            long sinceEpochMillis,
            byte[] dataSha256,
            List<ManifestEntry> entries
    ) {
    }
}
