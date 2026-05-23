package com.antivirus;

import com.antivirus.binary.BinaryProtocolProperties;
import com.antivirus.binary.BinaryReader;
import com.antivirus.binary.ExportType;
import com.antivirus.binary.MultipartMixedTestParser;
import com.antivirus.binary.StatusCodeMapper;
import com.antivirus.malware.MalwareSignatureEntity;
import com.antivirus.malware.MalwareSignaturePayload;
import com.antivirus.malware.MalwareSignatureAuditRepository;
import com.antivirus.malware.MalwareSignatureHistoryRepository;
import com.antivirus.malware.MalwareSignatureRepository;
import com.antivirus.signature.SignatureService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.security.MessageDigest;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Интеграционный тест бинарного API.
 *
 * <p>Проверяет, что:</p>
 * <ul>
 *     <li>каждый эндпоинт возвращает {@code multipart/mixed} с двумя частями
 *         {@code manifest.bin} и {@code data.bin};</li>
 *     <li>FULL не содержит DELETED, INCREMENT содержит, BY_IDS отдаёт ровно запрошенные;</li>
 *     <li>SHA-256 в манифесте совпадает с SHA-256 от data.bin;</li>
 *     <li>подпись манифеста верифицируется через {@code SignatureService.verifyBytes};</li>
 *     <li>подпись каждой записи в манифесте равна её существующему {@code digitalSignatureBase64}
 *         (запись <b>не</b> подписывается заново при экспорте);</li>
 *     <li>BAD_REQUEST для увлекшегося increment без параметра.</li>
 * </ul>
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "TLS_ENABLED=false",
        "DB_URL=jdbc:h2:mem:binarydb;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE",
        "DB_USERNAME=sa",
        "DB_PASSWORD=",
        "DB_DRIVER_CLASS_NAME=org.h2.Driver",
        "spring.jpa.hibernate.ddl-auto=validate",
        "server.ssl.key-store=classpath:test-keystore.p12",
        "server.ssl.key-store-password=changeit",
        "server.ssl.key-alias=server",
        "signature.key-store-path=classpath:test-keystore.p12",
        "signature.key-store-password=changeit",
        "signature.key-alias=server",
        "binary.surname=Polyatykin",
        "binary.manifest-version=1",
        "binary.data-version=1"
})
class BinarySignatureFlowIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private SignatureService signatureService;

    @Autowired
    private MalwareSignatureRepository signatureRepository;

    @Autowired
    private MalwareSignatureHistoryRepository historyRepository;

    @Autowired
    private MalwareSignatureAuditRepository auditRepository;

    @Autowired
    private BinaryProtocolProperties binaryProperties;

    @BeforeEach
    void cleanSignatureTables() {
        // Тесты используют одну in-memory БД и были бы зависимы друг от друга,
        // поэтому каждое выполнение начинаем с пустых таблиц сигнатур.
        auditRepository.deleteAll();
        historyRepository.deleteAll();
        signatureRepository.deleteAll();
    }

    @Test
    void fullExportReturnsOnlyActualAndVerifiableManifest() throws Exception {
        String adminAccess = login("admin", "admin12345");
        Instant before = Instant.now().minusSeconds(2);

        UUID id1 = createSignature(adminAccess, "Trojan.Bin.A", "deadbeef", "11223344", 100, "EXE", 0, 50);
        UUID id2 = createSignature(adminAccess, "Worm.Bin.B", "ff00", "5566", 200, "DLL", 10, 60);
        UUID id3 = createSignature(adminAccess, "Adware.Bin.C", "ab", "cd", 16, "PDF", 0, 16);

        // удалённая запись попадёт в инкремент, но не в FULL
        mockMvc.perform(delete("/api/signatures/" + id3)
                        .header("Authorization", "Bearer " + adminAccess))
                .andExpect(status().isNoContent());

        MvcResult full = mockMvc.perform(get("/api/binary/signatures/full")
                        .header("Authorization", "Bearer " + adminAccess))
                .andExpect(status().isOk())
                .andReturn();

        Parsed parsed = parseMultipart(full);
        assertEquals(2, parsed.entries.length, "FULL содержит только ACTUAL");
        Set<UUID> ids = collectIds(parsed.entries);
        assertEquals(new HashSet<>(Arrays.asList(id1, id2)), ids);

        assertManifestHeader(parsed, ExportType.FULL, -1L, 2);
        assertDataSha256Matches(parsed);
        assertManifestSignatureVerifies(parsed);
        assertEachRecordSignatureMatchesEntity(parsed.entries);

        // FULL не должен содержать DELETED
        for (ParsedEntry entry : parsed.entries) {
            assertEquals(StatusCodeMapper.ACTUAL_CODE, entry.statusCode,
                    "В FULL не должно быть DELETED записей");
        }

        // increment с тем же since должен содержать DELETED тоже
        String sinceParam = before.toString();
        MvcResult increment = mockMvc.perform(get("/api/binary/signatures/increment")
                        .param("since", sinceParam)
                        .header("Authorization", "Bearer " + adminAccess))
                .andExpect(status().isOk())
                .andReturn();
        Parsed incParsed = parseMultipart(increment);
        assertEquals(3, incParsed.entries.length, "INCREMENT содержит DELETED");
        assertManifestHeader(incParsed, ExportType.INCREMENT, before.toEpochMilli(), 3);
        assertManifestSignatureVerifies(incParsed);
        assertDataSha256Matches(incParsed);

        boolean foundDeleted = false;
        for (ParsedEntry entry : incParsed.entries) {
            if (entry.id.equals(id3)) {
                assertEquals(StatusCodeMapper.DELETED_CODE, entry.statusCode);
                foundDeleted = true;
            }
        }
        assertTrue(foundDeleted, "DELETED-запись должна присутствовать в инкременте");
    }

    @Test
    void incrementWithoutSinceReturnsBadRequest() throws Exception {
        String adminAccess = login("admin", "admin12345");
        mockMvc.perform(get("/api/binary/signatures/increment")
                        .header("Authorization", "Bearer " + adminAccess))
                .andExpect(status().isBadRequest());
    }

    @Test
    void byIdsReturnsOnlyRequestedRecords() throws Exception {
        String adminAccess = login("admin", "admin12345");

        UUID idA = createSignature(adminAccess, "Trojan.Bin.X", "01020304", "aabbccdd", 8, "EXE", 0, 8);
        UUID idB = createSignature(adminAccess, "Trojan.Bin.Y", "f0f0", "0102", 16, "DLL", 0, 16);

        String body = "{\"ids\":[\"" + idA + "\"]}";
        MvcResult result = mockMvc.perform(post("/api/binary/signatures/by-ids")
                        .header("Authorization", "Bearer " + adminAccess)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andReturn();

        Parsed parsed = parseMultipart(result);
        assertEquals(1, parsed.entries.length);
        assertEquals(idA, parsed.entries[0].id);
        assertManifestHeader(parsed, ExportType.BY_IDS, -1L, 1);
        assertManifestSignatureVerifies(parsed);

        // sanity: запись idB существует в БД, но в by-ids выдачу не попала
        assertNotNull(signatureRepository.findById(idB).orElseThrow());
    }

    private UUID createSignature(String token, String name, String firstHex, String hashHex,
                                 long remLen, String fileType, long offStart, long offEnd) throws Exception {
        String body = String.format("""
                {
                  "threatName": "%s",
                  "firstBytesHex": "%s",
                  "remainderHashHex": "%s",
                  "remainderLength": %d,
                  "fileType": "%s",
                  "offsetStart": %d,
                  "offsetEnd": %d
                }
                """, name, firstHex, hashHex, remLen, fileType, offStart, offEnd);
        MvcResult r = mockMvc.perform(post("/api/signatures")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isCreated())
                .andReturn();
        return UUID.fromString(objectMapper.readTree(r.getResponse().getContentAsString())
                .get("id").asText());
    }

    private String login(String username, String password) throws Exception {
        String body = String.format("""
                {"username": "%s", "password": "%s"}
                """, username, password);
        MvcResult r = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isOk())
                .andReturn();
        JsonNode json = objectMapper.readTree(r.getResponse().getContentAsString());
        return json.get("accessToken").asText();
    }

    private Parsed parseMultipart(MvcResult result) {
        String contentType = result.getResponse().getContentType();
        assertNotNull(contentType, "Content-Type должен быть выставлен");
        assertTrue(contentType.startsWith("multipart/mixed"), "Ожидаем multipart/mixed, получили " + contentType);
        String boundary = MultipartMixedTestParser.extractBoundary(contentType);
        Map<String, byte[]> parts = MultipartMixedTestParser.parse(result.getResponse().getContentAsByteArray(), boundary);
        assertTrue(parts.containsKey("manifest.bin"), "Должна быть часть manifest.bin");
        assertTrue(parts.containsKey("data.bin"), "Должна быть часть data.bin");

        byte[] manifestBytes = parts.get("manifest.bin");
        byte[] dataBytes = parts.get("data.bin");

        ParsedManifest manifest = parseManifest(manifestBytes);
        return new Parsed(manifestBytes, dataBytes, manifest.entries, manifest);
    }

    private ParsedManifest parseManifest(byte[] manifestBytes) {
        BinaryReader r = new BinaryReader(manifestBytes);
        String magic = r.readUtf8WithU16Length();
        assertEquals(binaryProperties.manifestMagic(), magic);
        int version = r.readU16BE();
        assertEquals(binaryProperties.getManifestVersion(), version);
        int exportType = r.readU8();
        long generatedAt = r.readI64BE();
        long sinceMillis = r.readI64BE();
        int recordCount = (int) r.readU32BE();
        byte[] dataSha = r.readBytesRaw(32);

        ParsedEntry[] entries = new ParsedEntry[recordCount];
        for (int i = 0; i < recordCount; i++) {
            UUID id = r.readUuid();
            byte status = (byte) r.readU8();
            long updatedAt = r.readI64BE();
            long offset = r.readI64BE();
            int length = (int) r.readU32BE();
            byte[] sig = r.readBytesWithU32Length();
            entries[i] = new ParsedEntry(id, status, updatedAt, offset, length, sig);
        }
        int trailerStart = r.position();
        byte[] manifestSignature = r.readBytesWithU32Length();
        return new ParsedManifest(magic, version, exportType, generatedAt, sinceMillis,
                dataSha, entries, manifestSignature, trailerStart);
    }

    private void assertManifestHeader(Parsed parsed, ExportType expectedType, long expectedSinceMillis, int expectedCount) {
        assertEquals(expectedType.code(), (byte) parsed.manifest.exportType,
                "exportType должен соответствовать запрошенному эндпоинту");
        assertEquals(expectedSinceMillis, parsed.manifest.sinceMillis);
        assertEquals(expectedCount, parsed.entries.length);
    }

    private void assertDataSha256Matches(Parsed parsed) throws Exception {
        byte[] expected = MessageDigest.getInstance("SHA-256").digest(parsed.dataBytes);
        assertArrayEquals(expected, parsed.manifest.dataSha,
                "SHA-256 в манифесте должен совпадать с SHA-256 от data.bin");
    }

    private void assertManifestSignatureVerifies(Parsed parsed) {
        byte[] unsigned = Arrays.copyOfRange(parsed.manifestBytes, 0, parsed.manifest.trailerStart);
        assertTrue(signatureService.verifyBytes(unsigned, parsed.manifest.manifestSignature),
                "Подпись манифеста должна верифицироваться публичным ключом");
    }

    private void assertEachRecordSignatureMatchesEntity(ParsedEntry[] entries) {
        for (ParsedEntry entry : entries) {
            MalwareSignatureEntity stored = signatureRepository.findById(entry.id).orElseThrow();
            byte[] expected = Base64.getDecoder().decode(stored.getDigitalSignatureBase64());
            assertArrayEquals(expected, entry.recordSignature,
                    "Подпись записи в манифесте равна digitalSignatureBase64 (запись не пересчитывается)");
            // и эта подпись действительно валидна для payload записи
            String base64 = Base64.getEncoder().encodeToString(entry.recordSignature);
            assertTrue(signatureService.verify(MalwareSignaturePayload.from(stored), base64),
                    "Подпись записи проходит верификацию payload-методом, как и для JSON API");
        }
    }

    private static Set<UUID> collectIds(ParsedEntry[] entries) {
        Set<UUID> ids = new LinkedHashSet<>();
        for (ParsedEntry e : entries) {
            ids.add(e.id);
        }
        return ids;
    }

    private record Parsed(byte[] manifestBytes, byte[] dataBytes, ParsedEntry[] entries, ParsedManifest manifest) {
    }

    private record ParsedManifest(String magic, int version, int exportType,
                                  long generatedAt, long sinceMillis,
                                  byte[] dataSha, ParsedEntry[] entries,
                                  byte[] manifestSignature, int trailerStart) {
    }

    private record ParsedEntry(UUID id, byte statusCode, long updatedAtEpochMillis,
                               long dataOffset, int dataLength, byte[] recordSignature) {
    }
}
