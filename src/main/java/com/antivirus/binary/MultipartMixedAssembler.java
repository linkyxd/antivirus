package com.antivirus.binary;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

/**
 * Сборщик HTTP-ответа в формате {@code multipart/mixed}.
 *
 * <p>Каждая часть имеет свои заголовки {@code Content-Disposition} и {@code Content-Type}
 * и отделяется от соседей строкой {@code --<boundary>}. После последней части идёт
 * закрывающая граница {@code --<boundary>--}. Между заголовками и телом — пустая строка
 * (двойной {@code CRLF}), как требует RFC 2046.</p>
 *
 * <p>Порядок частей зафиксирован: сначала {@code manifest.bin}, затем {@code data.bin}.
 * Это упрощает разбор на клиенте и интеграционное тестирование.</p>
 */
@Component
public class MultipartMixedAssembler {

    private static final String MANIFEST_FILENAME = "manifest.bin";
    private static final String DATA_FILENAME = "data.bin";
    private static final String CRLF = "\r\n";

    public ResponseEntity<byte[]> assemble(BinaryExportResult export) {
        String boundary = generateBoundary();
        byte[] body = buildBody(export, boundary);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.parseMediaType("multipart/mixed; boundary=" + boundary));
        headers.setContentLength(body.length);
        return ResponseEntity.ok().headers(headers).body(body);
    }

    private static String generateBoundary() {
        return "antivirus-binary-" + UUID.randomUUID();
    }

    private static byte[] buildBody(BinaryExportResult export, String boundary) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            writePart(out, boundary, MANIFEST_FILENAME, export.manifest());
            writePart(out, boundary, DATA_FILENAME, export.data());
            out.write(("--" + boundary + "--" + CRLF).getBytes(StandardCharsets.US_ASCII));
        } catch (IOException e) {
            throw new IllegalStateException("Unexpected IO error in multipart assembly", e);
        }
        return out.toByteArray();
    }

    private static void writePart(ByteArrayOutputStream out, String boundary, String filename, byte[] payload)
            throws IOException {
        StringBuilder header = new StringBuilder();
        header.append("--").append(boundary).append(CRLF);
        header.append("Content-Disposition: attachment; filename=\"").append(filename).append("\"").append(CRLF);
        header.append("Content-Type: application/octet-stream").append(CRLF);
        header.append("Content-Length: ").append(payload.length).append(CRLF);
        header.append(CRLF);
        out.write(header.toString().getBytes(StandardCharsets.US_ASCII));
        out.write(payload);
        out.write(CRLF.getBytes(StandardCharsets.US_ASCII));
    }
}
