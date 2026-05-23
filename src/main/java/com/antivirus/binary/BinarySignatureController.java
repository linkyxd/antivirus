package com.antivirus.binary;

import com.antivirus.malware.dto.GetByIdsRequest;
import jakarta.validation.Valid;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;

/**
 * REST API бинарной выгрузки сигнатур.
 *
 * <p>Каждый эндпоинт возвращает {@code multipart/mixed} с двумя частями:
 * {@code manifest.bin} (с подписью манифеста и подписями записей) и {@code data.bin}
 * (полезная нагрузка сигнатур в бинарном виде).</p>
 *
 * <p>Авторизация задаётся в {@code SecurityConfig}: чтение разрешено любому
 * аутентифицированному клиенту (USER+), потому что бинарную базу скачивают агенты
 * антивируса на устройствах пользователей.</p>
 */
@RestController
@RequestMapping("/api/binary/signatures")
public class BinarySignatureController {

    private final BinarySignatureExportService exportService;
    private final MultipartMixedAssembler multipartAssembler;

    public BinarySignatureController(BinarySignatureExportService exportService,
                                     MultipartMixedAssembler multipartAssembler) {
        this.exportService = exportService;
        this.multipartAssembler = multipartAssembler;
    }

    @GetMapping("/full")
    public ResponseEntity<byte[]> full() {
        BinaryExportResult result = exportService.exportFull();
        return multipartAssembler.assemble(result);
    }

    @GetMapping("/increment")
    public ResponseEntity<byte[]> increment(
            @RequestParam("since")
            @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) Instant since) {
        BinaryExportResult result = exportService.exportIncrement(since);
        return multipartAssembler.assemble(result);
    }

    @PostMapping("/by-ids")
    public ResponseEntity<byte[]> byIds(@Valid @RequestBody GetByIdsRequest request) {
        BinaryExportResult result = exportService.exportByIds(request.ids());
        return multipartAssembler.assemble(result);
    }
}
