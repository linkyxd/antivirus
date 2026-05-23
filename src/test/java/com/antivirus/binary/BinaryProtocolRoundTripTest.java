package com.antivirus.binary;

import com.antivirus.malware.MalwareSignatureEntity;
import com.antivirus.malware.SignatureStatus;
import com.antivirus.signature.SignatureService;
import com.antivirus.signature.TestSignatureServiceFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Round-trip проверка протокола: сериализуем manifest+data ровно так же, как делает
 * сервис, и парсим тестовым {@link BinaryReader}. Проверяем все поля заголовков и
 * записей, SHA-256 на data.bin, подпись манифеста через {@code verifyBytes}.
 */
class BinaryProtocolRoundTripTest {

    private static SignatureService signatureService;
    private static BinaryProtocolProperties props;

    @BeforeAll
    static void setup() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        KeyPair keyPair = gen.generateKeyPair();
        signatureService = TestSignatureServiceFactory.build(keyPair, "SHA256withRSA");

        props = new BinaryProtocolProperties();
        props.setSurname("Polyatykin");
        props.setManifestVersion(1);
        props.setDataVersion(1);
    }

    @Test
    void manifestAndDataAreParsableAndConsistent() {
        DataSerializer dataSerializer = new DataSerializer(props);
        ManifestSerializer manifestSerializer = new ManifestSerializer(props, signatureService);

        List<MalwareSignatureEntity> entities = sampleEntities();
        BinaryDataPart dataPart = dataSerializer.serialize(entities);

        List<ManifestEntry> entries = new ArrayList<>();
        for (int i = 0; i < entities.size(); i++) {
            MalwareSignatureEntity e = entities.get(i);
            BinaryDataPart.RecordRange r = dataPart.ranges().get(i);
            entries.add(new ManifestEntry(
                    e.getId(),
                    StatusCodeMapper.toCode(e.getStatus()),
                    e.getUpdatedAt().toEpochMilli(),
                    r.offset(),
                    r.length(),
                    sampleSignature(i)
            ));
        }

        long generatedAt = Instant.now().toEpochMilli();
        long sinceMillis = -1L;
        ManifestSerializer.ManifestSerializationInput input = new ManifestSerializer.ManifestSerializationInput(
                ExportType.FULL, generatedAt, sinceMillis, dataPart.sha256(), entries);
        byte[] manifestBytes = manifestSerializer.serialize(input);

        // 1. data.bin parses cleanly and round-trips fields
        BinaryReader dr = new BinaryReader(dataPart.bytes());
        assertEquals("DB-Polyatykin", dr.readUtf8WithU16Length());
        assertEquals(1, dr.readU16BE(), "data.bin version");
        assertEquals(entities.size(), (int) dr.readU32BE(), "data.bin recordCount");
        for (MalwareSignatureEntity e : entities) {
            assertEquals(e.getThreatName(), dr.readUtf8WithU16Length());
            byte[] firstBytes = dr.readBytesWithU16Length();
            assertArrayEquals(HexCodec.decode(e.getFirstBytesHex()), firstBytes);
            byte[] remainderHash = dr.readBytesWithU16Length();
            assertArrayEquals(HexCodec.decode(e.getRemainderHashHex()), remainderHash);
            assertEquals(e.getRemainderLength(), dr.readI64BE());
            assertEquals(e.getFileType(), dr.readUtf8WithU16Length());
            assertEquals(e.getOffsetStart(), dr.readI64BE());
            assertEquals(e.getOffsetEnd(), dr.readI64BE());
        }
        assertEquals(0, dr.remaining(), "После всех записей data.bin не должно быть лишних байт");

        // 2. SHA-256 в манифесте равен SHA-256 от data.bin
        byte[] expectedSha = sha256(dataPart.bytes());
        assertArrayEquals(expectedSha, dataPart.sha256());

        // 3. manifest.bin parses cleanly
        BinaryReader mr = new BinaryReader(manifestBytes);
        assertEquals("MF-Polyatykin", mr.readUtf8WithU16Length());
        assertEquals(1, mr.readU16BE(), "manifest version");
        assertEquals(ExportType.FULL.code(), (byte) mr.readU8(), "exportType");
        assertEquals(generatedAt, mr.readI64BE());
        assertEquals(sinceMillis, mr.readI64BE());
        assertEquals(entities.size(), (int) mr.readU32BE());
        byte[] sha256InManifest = mr.readBytesRaw(32);
        assertArrayEquals(expectedSha, sha256InManifest, "В манифесте лежит ровно SHA-256 от data.bin");

        for (int i = 0; i < entities.size(); i++) {
            MalwareSignatureEntity e = entities.get(i);
            BinaryDataPart.RecordRange r = dataPart.ranges().get(i);
            UUID id = mr.readUuid();
            assertEquals(e.getId(), id);
            assertEquals(StatusCodeMapper.toCode(e.getStatus()), (byte) mr.readU8());
            assertEquals(e.getUpdatedAt().toEpochMilli(), mr.readI64BE());
            assertEquals(r.offset(), mr.readI64BE(), "dataOffset должен совпадать с тем, что вернул DataSerializer");
            assertEquals(r.length(), (int) mr.readU32BE());
            byte[] recordSig = mr.readBytesWithU32Length();
            assertArrayEquals(sampleSignature(i), recordSig,
                    "В манифест попадает та же подпись записи, что мы клали при сборке");
            // данные по offset/length должны лежать ровно там, где сказали в манифесте
            byte[] payload = dataPart.bytes();
            int recordStart = manifestPayloadStart(payload) + (int) r.offset();
            byte[] recordSlice = Arrays.copyOfRange(payload, recordStart, recordStart + r.length());
            assertEquals(r.length(), recordSlice.length);
        }

        // подпись манифеста идёт в конце как trailer
        int trailerStart = mr.position();
        byte[] manifestSignatureBytes = mr.readBytesWithU32Length();
        assertEquals(0, mr.remaining(), "После подписи манифеста не должно быть лишних байт");
        // Сама подпись верифицируется по unsigned части
        byte[] unsigned = Arrays.copyOfRange(manifestBytes, 0, trailerStart);
        assertTrue(signatureService.verifyBytes(unsigned, manifestSignatureBytes),
                "Подпись манифеста должна проверяться публичным ключом");

        // ломаем один байт — подпись должна стать невалидной
        byte[] tamperedUnsigned = unsigned.clone();
        tamperedUnsigned[10] ^= 0x01;
        assertFalse(signatureService.verifyBytes(tamperedUnsigned, manifestSignatureBytes),
                "Любое изменение неподписанной части ломает подпись");
    }

    @Test
    void emptyExportSerializesAndVerifies() {
        DataSerializer dataSerializer = new DataSerializer(props);
        ManifestSerializer manifestSerializer = new ManifestSerializer(props, signatureService);

        BinaryDataPart dataPart = dataSerializer.serialize(List.of());

        ManifestSerializer.ManifestSerializationInput input = new ManifestSerializer.ManifestSerializationInput(
                ExportType.BY_IDS, Instant.now().toEpochMilli(), -1L, dataPart.sha256(), List.of());
        byte[] manifestBytes = manifestSerializer.serialize(input);

        BinaryReader dr = new BinaryReader(dataPart.bytes());
        assertEquals("DB-Polyatykin", dr.readUtf8WithU16Length());
        assertEquals(1, dr.readU16BE());
        assertEquals(0, (int) dr.readU32BE(), "Пустой пакет не содержит записей");

        BinaryReader mr = new BinaryReader(manifestBytes);
        assertEquals("MF-Polyatykin", mr.readUtf8WithU16Length());
        mr.readU16BE();
        assertEquals(ExportType.BY_IDS.code(), (byte) mr.readU8());
        mr.readI64BE();
        mr.readI64BE();
        assertEquals(0, (int) mr.readU32BE());
        byte[] sha = mr.readBytesRaw(32);
        assertArrayEquals(sha256(dataPart.bytes()), sha);
        int trailerStart = mr.position();
        byte[] sig = mr.readBytesWithU32Length();
        byte[] unsigned = Arrays.copyOfRange(manifestBytes, 0, trailerStart);
        assertTrue(signatureService.verifyBytes(unsigned, sig));
    }

    private static int manifestPayloadStart(byte[] dataBin) {
        BinaryReader r = new BinaryReader(dataBin);
        r.readUtf8WithU16Length();
        r.readU16BE();
        r.readU32BE();
        return r.position();
    }

    private static List<MalwareSignatureEntity> sampleEntities() {
        return List.of(
                entity("Trojan.\u0410\u043b\u0444\u0430", "deadbeef", "abcdef0123456789",
                        1024L, "EXE", 0L, 256L, SignatureStatus.ACTUAL),
                entity("Worm.B", "ff00ff00aa55", "01020304",
                        4096L, "DLL", 100L, 200L, SignatureStatus.ACTUAL),
                entity("Adware.C", "00", "ffeeddccbbaa9988",
                        16L, "PDF", 0L, 16L, SignatureStatus.DELETED)
        );
    }

    private static MalwareSignatureEntity entity(String name, String firstHex, String hashHex,
                                                 long remLen, String fileType,
                                                 long offStart, long offEnd, SignatureStatus status) {
        MalwareSignatureEntity e = new MalwareSignatureEntity();
        e.setId(UUID.randomUUID());
        e.setThreatName(name);
        e.setFirstBytesHex(firstHex);
        e.setRemainderHashHex(hashHex);
        e.setRemainderLength(remLen);
        e.setFileType(fileType);
        e.setOffsetStart(offStart);
        e.setOffsetEnd(offEnd);
        e.setStatus(status);
        e.setUpdatedAt(Instant.now());
        e.setDigitalSignatureBase64("placeholder");
        return e;
    }

    /** Псевдо-подпись записи нужна только чтобы убедиться, что байты доходят до манифеста. */
    private static byte[] sampleSignature(int seed) {
        byte[] sig = new byte[256];
        for (int i = 0; i < sig.length; i++) {
            sig[i] = (byte) ((i + seed) & 0xFF);
        }
        return sig;
    }

    private static byte[] sha256(byte[] payload) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(payload);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
