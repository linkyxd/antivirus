package com.antivirus.signature;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.stereotype.Component;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Канонизатор JSON по RFC 8785 (JSON Canonicalization Scheme, JCS).
 *
 * <p>Преобразует произвольный Java-объект сначала в JSON-дерево через Jackson, затем — в
 * детерминированную строку JSON и далее в UTF-8 байты. Это даёт воспроизводимое
 * представление, пригодное для подачи в криптографические примитивы (хеш/подпись).</p>
 *
 * <p>Реализуемые правила RFC 8785:</p>
 * <ul>
 *     <li>между токенами не выводятся пробелы и переносы строк;</li>
 *     <li>ключи объекта сортируются по UTF-16 code units (как беззнаковые);</li>
 *     <li>строки экранируются по правилам JSON: backslash-b/t/n/f/r и backslash-quote
 *         плюс backslash-u + 4 hex digits в нижнем регистре для управляющих символов
 *         U+0000..U+001F;</li>
 *     <li>одиночные суррогаты приводят к ошибке;</li>
 *     <li>целые числа выводятся без десятичной точки; для double используется
 *         ECMAScript-подобное представление; {@code NaN} и {@code Infinity} запрещены;</li>
 *     <li>итог кодируется в UTF-8.</li>
 * </ul>
 */
@Component
public class JsonCanonicalizer {

    private final ObjectMapper objectMapper;

    public JsonCanonicalizer() {
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    /**
     * Канонизирует payload: Java-объект -> JsonNode -> канонический JSON -> UTF-8 байты.
     */
    public byte[] canonicalize(Object payload) {
        return canonicalize(toJsonTree(payload));
    }

    /**
     * Канонизирует уже построенное JSON-дерево.
     */
    public byte[] canonicalize(JsonNode root) {
        StringBuilder sb = new StringBuilder();
        write(root, sb);
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private JsonNode toJsonTree(Object payload) {
        try {
            return objectMapper.valueToTree(payload);
        } catch (IllegalArgumentException e) {
            throw new SignatureException(SignatureException.Category.CRYPTO,
                    "Cannot convert payload to JSON tree", e);
        }
    }

    private void write(JsonNode node, StringBuilder out) {
        if (node == null || node.isNull() || node.isMissingNode()) {
            out.append("null");
            return;
        }
        switch (node.getNodeType()) {
            case OBJECT -> writeObject((ObjectNode) node, out);
            case ARRAY -> writeArray(node, out);
            case STRING -> writeString(node.textValue(), out);
            case BOOLEAN -> out.append(node.booleanValue() ? "true" : "false");
            case NUMBER -> writeNumber(node, out);
            default -> throw new SignatureException(SignatureException.Category.CRYPTO,
                    "Unsupported JSON node type: " + node.getNodeType());
        }
    }

    private void writeObject(ObjectNode node, StringBuilder out) {
        List<Map.Entry<String, JsonNode>> entries = new ArrayList<>(node.size());
        Iterator<Map.Entry<String, JsonNode>> fields = node.fields();
        while (fields.hasNext()) {
            entries.add(fields.next());
        }
        entries.sort((a, b) -> compareUtf16(a.getKey(), b.getKey()));

        out.append('{');
        boolean first = true;
        for (Map.Entry<String, JsonNode> e : entries) {
            if (!first) {
                out.append(',');
            }
            writeString(e.getKey(), out);
            out.append(':');
            write(e.getValue(), out);
            first = false;
        }
        out.append('}');
    }

    private void writeArray(JsonNode node, StringBuilder out) {
        out.append('[');
        boolean first = true;
        for (Iterator<JsonNode> it = node.elements(); it.hasNext(); ) {
            if (!first) {
                out.append(',');
            }
            write(it.next(), out);
            first = false;
        }
        out.append(']');
    }

    private void writeString(String s, StringBuilder out) {
        out.append('"');
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\' -> out.append("\\\\");
                case '"' -> out.append("\\\"");
                case '\b' -> out.append("\\b");
                case '\t' -> out.append("\\t");
                case '\n' -> out.append("\\n");
                case '\f' -> out.append("\\f");
                case '\r' -> out.append("\\r");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
                    } else if (Character.isHighSurrogate(c)) {
                        if (i + 1 < s.length() && Character.isLowSurrogate(s.charAt(i + 1))) {
                            out.append(c);
                            out.append(s.charAt(++i));
                        } else {
                            throw new SignatureException(SignatureException.Category.CRYPTO,
                                    "Lone high surrogate at index " + i);
                        }
                    } else if (Character.isLowSurrogate(c)) {
                        throw new SignatureException(SignatureException.Category.CRYPTO,
                                "Lone low surrogate at index " + i);
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        out.append('"');
    }

    private void writeNumber(JsonNode node, StringBuilder out) {
        if (node.isIntegralNumber()) {
            if (node.canConvertToLong()) {
                out.append(Long.toString(node.longValue()));
            } else {
                out.append(node.bigIntegerValue().toString());
            }
            return;
        }

        double d;
        if (node.isBigDecimal()) {
            BigDecimal bd = node.decimalValue();
            d = bd.doubleValue();
        } else {
            d = node.doubleValue();
        }
        if (Double.isNaN(d) || Double.isInfinite(d)) {
            throw new SignatureException(SignatureException.Category.CRYPTO,
                    "NaN/Infinity is not allowed in canonical JSON");
        }
        out.append(formatEcmaScriptNumber(d));
    }

    /**
     * Упрощённое ECMAScript-подобное представление числа {@code double}.
     *
     * <p>Покрывает практический случай Ticket-а лицензии, где числа — целые. Для целых
     * значений в пределах 64-битного {@code long} возвращает строку без десятичной точки;
     * остальное делегирует {@link Double#toString(double)}. Отрицательный ноль
     * нормализуется к {@code "0"} в соответствии с {@code Number.prototype.toString(-0)}.</p>
     */
    private static String formatEcmaScriptNumber(double d) {
        if (d == 0.0) {
            return "0";
        }
        if (d == Math.floor(d) && Math.abs(d) < 1e21) {
            long asLong = (long) d;
            if ((double) asLong == d) {
                return Long.toString(asLong);
            }
        }
        return Double.toString(d);
    }

    private static int compareUtf16(String a, String b) {
        int la = a.length();
        int lb = b.length();
        int n = Math.min(la, lb);
        for (int i = 0; i < n; i++) {
            int ca = a.charAt(i);
            int cb = b.charAt(i);
            if (ca != cb) {
                return ca - cb;
            }
        }
        return la - lb;
    }
}
