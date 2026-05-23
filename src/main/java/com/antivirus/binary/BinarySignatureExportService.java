package com.antivirus.binary;

import com.antivirus.malware.MalwareSignatureEntity;
import com.antivirus.malware.MalwareSignatureService;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

/**
 * Оркестратор бинарной выгрузки сигнатур.
 *
 * <p>Получает данные из {@link MalwareSignatureService}, превращает их в
 * {@code data.bin} через {@link DataSerializer}, собирает entries манифеста (с уже
 * существующими подписями записей) и подписывает манифест через
 * {@link ManifestSerializer}.</p>
 *
 * <p>Подпись каждой записи (поле {@code digitalSignatureBase64}) <b>не пересчитывается</b> —
 * она уже была вычислена при create/update. В манифест попадает её декодированный
 * сырой байтовый вид.</p>
 */
@Service
public class BinarySignatureExportService {

    private static final long SINCE_NOT_APPLICABLE = -1L;

    private final MalwareSignatureService malwareSignatureService;
    private final DataSerializer dataSerializer;
    private final ManifestSerializer manifestSerializer;

    public BinarySignatureExportService(MalwareSignatureService malwareSignatureService,
                                        DataSerializer dataSerializer,
                                        ManifestSerializer manifestSerializer) {
        this.malwareSignatureService = malwareSignatureService;
        this.dataSerializer = dataSerializer;
        this.manifestSerializer = manifestSerializer;
    }

    public BinaryExportResult exportFull() {
        List<MalwareSignatureEntity> records = malwareSignatureService.getAllActual();
        return assemble(records, ExportType.FULL, SINCE_NOT_APPLICABLE);
    }

    public BinaryExportResult exportIncrement(Instant since) {
        List<MalwareSignatureEntity> records = malwareSignatureService.getIncrement(since);
        return assemble(records, ExportType.INCREMENT, since.toEpochMilli());
    }

    public BinaryExportResult exportByIds(Collection<UUID> ids) {
        List<MalwareSignatureEntity> records = malwareSignatureService.getByIds(ids);
        return assemble(records, ExportType.BY_IDS, SINCE_NOT_APPLICABLE);
    }

    private BinaryExportResult assemble(List<MalwareSignatureEntity> records,
                                        ExportType exportType,
                                        long sinceEpochMillis) {
        BinaryDataPart dataPart = dataSerializer.serialize(records);
        List<ManifestEntry> entries = buildEntries(records, dataPart.ranges());

        ManifestSerializer.ManifestSerializationInput input = new ManifestSerializer.ManifestSerializationInput(
                exportType,
                Instant.now().toEpochMilli(),
                sinceEpochMillis,
                dataPart.sha256(),
                entries
        );
        byte[] manifest = manifestSerializer.serialize(input);
        return new BinaryExportResult(manifest, dataPart.bytes());
    }

    private static List<ManifestEntry> buildEntries(List<MalwareSignatureEntity> records,
                                                    List<BinaryDataPart.RecordRange> ranges) {
        if (records.size() != ranges.size()) {
            throw new IllegalStateException("records and ranges size mismatch: "
                    + records.size() + " vs " + ranges.size());
        }
        List<ManifestEntry> entries = new ArrayList<>(records.size());
        for (int i = 0; i < records.size(); i++) {
            MalwareSignatureEntity entity = records.get(i);
            BinaryDataPart.RecordRange range = ranges.get(i);
            byte[] recordSignature = decodeRecordSignature(entity.getDigitalSignatureBase64(), entity.getId());
            entries.add(new ManifestEntry(
                    entity.getId(),
                    StatusCodeMapper.toCode(entity.getStatus()),
                    entity.getUpdatedAt().toEpochMilli(),
                    range.offset(),
                    range.length(),
                    recordSignature
            ));
        }
        return entries;
    }

    private static byte[] decodeRecordSignature(String base64, UUID id) {
        if (base64 == null || base64.isBlank()) {
            throw new IllegalStateException("Signature is missing for record " + id);
        }
        try {
            return Base64.getDecoder().decode(base64);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("Invalid Base64 signature stored for record " + id, e);
        }
    }
}
