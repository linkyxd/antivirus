package com.antivirus.binary;

import com.antivirus.malware.MalwareSignatureEntity;
import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;

/**
 * Сериализатор бинарного файла {@code data.bin}.
 *
 * <p>Структура:</p>
 * <pre>
 * header:
 *     uint16 magicLength
 *     bytes  magic ("DB-&lt;surname&gt;")
 *     uint16 version
 *     uint32 recordCount
 *
 * record (recordCount раз):
 *     uint16 + bytes  threatName (UTF-8)
 *     uint16 + bytes  firstBytes (raw, hex декодирован)
 *     uint16 + bytes  remainderHash (raw, hex декодирован)
 *     int64           remainderLength
 *     uint16 + bytes  fileType (UTF-8)
 *     int64           offsetStart
 *     int64           offsetEnd
 * </pre>
 *
 * <p>В data.bin намеренно нет {@code id, status, updatedAt, digitalSignatureBase64}: они
 * принадлежат манифесту (см. методичку, раздел 6.3).</p>
 */
@Component
public class DataSerializer {

    private final BinaryProtocolProperties properties;

    public DataSerializer(BinaryProtocolProperties properties) {
        this.properties = properties;
    }

    public BinaryDataPart serialize(List<MalwareSignatureEntity> signatures) {
        BinaryWriter writer = new BinaryWriter();
        writer.writeUtf8WithU16Length(properties.dataMagic());
        writer.writeU16BE(properties.getDataVersion());
        writer.writeU32BE(signatures.size());

        int payloadStart = writer.size();

        List<BinaryDataPart.RecordRange> ranges = new ArrayList<>(signatures.size());
        for (MalwareSignatureEntity entity : signatures) {
            int recordStart = writer.size();
            writeRecord(writer, entity);
            int recordEnd = writer.size();
            long offset = (long) recordStart - payloadStart;
            int length = recordEnd - recordStart;
            ranges.add(new BinaryDataPart.RecordRange(offset, length));
        }

        byte[] bytes = writer.toByteArray();
        byte[] sha256 = sha256(bytes);
        return new BinaryDataPart(bytes, sha256, ranges);
    }

    private static void writeRecord(BinaryWriter writer, MalwareSignatureEntity e) {
        writer.writeUtf8WithU16Length(e.getThreatName());
        writer.writeBytesWithU16Length(HexCodec.decode(e.getFirstBytesHex()));
        writer.writeBytesWithU16Length(HexCodec.decode(e.getRemainderHashHex()));
        writer.writeI64BE(e.getRemainderLength());
        writer.writeUtf8WithU16Length(e.getFileType());
        writer.writeI64BE(e.getOffsetStart());
        writer.writeI64BE(e.getOffsetEnd());
    }

    private static byte[] sha256(byte[] payload) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(payload);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is not available in JVM", e);
        }
    }
}
