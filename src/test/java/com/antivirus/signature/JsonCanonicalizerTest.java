package com.antivirus.signature;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JsonCanonicalizerTest {

    private final JsonCanonicalizer canonicalizer = new JsonCanonicalizer();

    @Test
    void sortsObjectKeysByUtf16CodeUnits() {
        Map<String, Object> input = new LinkedHashMap<>();
        input.put("b", 1);
        input.put("a", 2);
        input.put("ab", 3);

        String json = new String(canonicalizer.canonicalize(input), StandardCharsets.UTF_8);

        assertEquals("{\"a\":2,\"ab\":3,\"b\":1}", json);
    }

    @Test
    void sortsRecursivelyAndDropsAllWhitespace() {
        Map<String, Object> inner = new LinkedHashMap<>();
        inner.put("y", true);
        inner.put("x", false);

        Map<String, Object> input = new LinkedHashMap<>();
        input.put("outer", inner);
        input.put("arr", List.of(1, 2, 3));

        String json = new String(canonicalizer.canonicalize(input), StandardCharsets.UTF_8);

        assertEquals("{\"arr\":[1,2,3],\"outer\":{\"x\":false,\"y\":true}}", json);
    }

    @Test
    void escapesControlCharsLowercaseHex() {
        Map<String, Object> input = Map.of("s", "\u0001\u001f");
        String json = new String(canonicalizer.canonicalize(input), StandardCharsets.UTF_8);
        assertEquals("{\"s\":\"\\u0001\\u001f\"}", json);
    }

    @Test
    void escapesShortFormsForCommonControlChars() {
        Map<String, Object> input = Map.of("s", "a\b\t\n\f\r\"\\b");
        String json = new String(canonicalizer.canonicalize(input), StandardCharsets.UTF_8);
        assertEquals("{\"s\":\"a\\b\\t\\n\\f\\r\\\"\\\\b\"}", json);
    }

    @Test
    void integerNumberHasNoFractionalPart() {
        Map<String, Object> input = Map.of("n", 42L);
        String json = new String(canonicalizer.canonicalize(input), StandardCharsets.UTF_8);
        assertEquals("{\"n\":42}", json);
    }

    @Test
    void rejectsNaNAndInfinity() {
        assertThrows(SignatureException.class, () ->
                canonicalizer.canonicalize(Map.of("n", Double.NaN)));
        assertThrows(SignatureException.class, () ->
                canonicalizer.canonicalize(Map.of("n", Double.POSITIVE_INFINITY)));
        assertThrows(SignatureException.class, () ->
                canonicalizer.canonicalize(Map.of("n", Double.NEGATIVE_INFINITY)));
    }

    @Test
    void roundTripDeterministicForSamePayload() {
        Map<String, Object> a = new LinkedHashMap<>();
        a.put("b", "y");
        a.put("a", "x");

        Map<String, Object> b = new LinkedHashMap<>();
        b.put("a", "x");
        b.put("b", "y");

        byte[] left = canonicalizer.canonicalize(a);
        byte[] right = canonicalizer.canonicalize(b);

        assertArrayEquals(left, right);
    }

    @Test
    void serializesInstantAsIsoString() {
        ObjectMapper mapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

        Instant fixed = Instant.parse("2024-05-19T12:00:00Z");
        Map<String, Object> input = Map.of("ts", fixed);

        String json = new String(canonicalizer.canonicalize(input), StandardCharsets.UTF_8);
        String expectedInstant = mapper.valueToTree(fixed).asText();
        assertEquals("{\"ts\":\"" + expectedInstant + "\"}", json);
    }
}
