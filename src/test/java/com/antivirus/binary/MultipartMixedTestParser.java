package com.antivirus.binary;

import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Простой тестовый парсер ответов {@code multipart/mixed}.
 *
 * <p>Берёт raw тело ответа и {@code boundary} из {@code Content-Type}, режет его на
 * части, парсит заголовки части и возвращает {@code Map&lt;filename, payload&gt;}. Этого
 * достаточно для тестов: настоящие production-парсеры покрывают больше edge-cases.</p>
 */
public final class MultipartMixedTestParser {

    private static final byte[] CRLF = {'\r', '\n'};
    private static final byte[] CRLF_CRLF = {'\r', '\n', '\r', '\n'};

    private MultipartMixedTestParser() {
    }

    public static Map<String, byte[]> parse(byte[] body, String boundary) {
        byte[] dashBoundary = ("--" + boundary).getBytes(StandardCharsets.US_ASCII);
        byte[] closeBoundary = ("--" + boundary + "--").getBytes(StandardCharsets.US_ASCII);

        Map<String, byte[]> parts = new LinkedHashMap<>();
        int cursor = 0;
        while (true) {
            int boundaryStart = indexOf(body, dashBoundary, cursor);
            if (boundaryStart < 0) {
                throw new IllegalStateException("Boundary not found at cursor=" + cursor);
            }
            // Это закрывающая граница?
            if (regionMatches(body, boundaryStart, closeBoundary)) {
                break;
            }
            int afterBoundary = boundaryStart + dashBoundary.length;
            // пропустить CRLF после boundary
            if (afterBoundary + 1 < body.length
                    && body[afterBoundary] == '\r' && body[afterBoundary + 1] == '\n') {
                afterBoundary += 2;
            }

            int headersEnd = indexOf(body, CRLF_CRLF, afterBoundary);
            if (headersEnd < 0) {
                throw new IllegalStateException("Headers terminator not found in part");
            }
            String headers = new String(body, afterBoundary, headersEnd - afterBoundary, StandardCharsets.US_ASCII);
            String filename = extractFilename(headers);

            int payloadStart = headersEnd + CRLF_CRLF.length;
            int nextBoundary = indexOf(body, dashBoundary, payloadStart);
            if (nextBoundary < 0) {
                throw new IllegalStateException("Next boundary missing after part: " + filename);
            }
            // отрезаем CRLF, который сервер пишет между концом тела и --boundary
            int payloadEnd = nextBoundary;
            if (payloadEnd >= 2
                    && body[payloadEnd - 2] == '\r' && body[payloadEnd - 1] == '\n') {
                payloadEnd -= 2;
            }

            byte[] payload = new byte[payloadEnd - payloadStart];
            System.arraycopy(body, payloadStart, payload, 0, payload.length);
            parts.put(filename, payload);
            cursor = nextBoundary;
        }
        return parts;
    }

    private static String extractFilename(String headers) {
        for (String line : headers.split("\r\n")) {
            String lower = line.toLowerCase();
            if (lower.startsWith("content-disposition")) {
                int idx = lower.indexOf("filename=");
                if (idx >= 0) {
                    String tail = line.substring(idx + "filename=".length()).trim();
                    if (tail.startsWith("\"") && tail.endsWith("\"") && tail.length() >= 2) {
                        return tail.substring(1, tail.length() - 1);
                    }
                    int semi = tail.indexOf(';');
                    return semi >= 0 ? tail.substring(0, semi) : tail;
                }
            }
        }
        throw new IllegalStateException("filename not found in headers: " + headers);
    }

    private static int indexOf(byte[] haystack, byte[] needle, int from) {
        outer:
        for (int i = from; i + needle.length <= haystack.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (haystack[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private static boolean regionMatches(byte[] haystack, int offset, byte[] expected) {
        if (offset + expected.length > haystack.length) {
            return false;
        }
        for (int i = 0; i < expected.length; i++) {
            if (haystack[offset + i] != expected[i]) {
                return false;
            }
        }
        return true;
    }

    public static String extractBoundary(String contentType) {
        String marker = "boundary=";
        int idx = contentType.indexOf(marker);
        if (idx < 0) {
            throw new IllegalStateException("boundary not found in Content-Type: " + contentType);
        }
        String tail = contentType.substring(idx + marker.length()).trim();
        int semi = tail.indexOf(';');
        if (semi >= 0) {
            tail = tail.substring(0, semi);
        }
        if (tail.startsWith("\"") && tail.endsWith("\"") && tail.length() >= 2) {
            tail = tail.substring(1, tail.length() - 1);
        }
        return tail;
    }
}
