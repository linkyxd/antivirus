package com.antivirus.signature;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SignatureServiceTest {

    private static KeyPair keyPair;

    @BeforeAll
    static void generateKeys() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        keyPair = gen.generateKeyPair();
    }

    private SignatureService buildService(String algorithm) {
        SignatureProperties properties = new SignatureProperties();
        properties.setAlgorithm(algorithm);
        SignatureKeyProvider provider = new SignatureKeyProvider(
                keyPair.getPrivate(), keyPair.getPublic(), null);
        JsonCanonicalizer canonicalizer = new JsonCanonicalizer();
        return new SignatureService(provider, canonicalizer, properties);
    }

    @Test
    void signsAndVerifiesPayload() {
        SignatureService service = buildService("SHA256withRSA");
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("userId", 1L);
        payload.put("blocked", false);
        payload.put("note", "ok");

        String signature = service.sign(payload);

        assertNotNull(signature);
        assertNotNull(Base64.getDecoder().decode(signature));
        assertTrue(service.verify(payload, signature));
    }

    @Test
    void signatureIsStableForEquivalentPayloads() {
        SignatureService service = buildService("SHA256withRSA");
        Map<String, Object> payloadAsc = new LinkedHashMap<>();
        payloadAsc.put("a", 1);
        payloadAsc.put("b", 2);

        Map<String, Object> payloadDesc = new LinkedHashMap<>();
        payloadDesc.put("b", 2);
        payloadDesc.put("a", 1);

        String signatureAsc = service.sign(payloadAsc);

        assertTrue(service.verify(payloadDesc, signatureAsc),
                "Подпись должна верифицироваться независимо от порядка ключей в исходном объекте");
    }

    @Test
    void verifyReturnsFalseForTamperedPayload() {
        SignatureService service = buildService("SHA256withRSA");
        Map<String, Object> payload = Map.of("userId", 1L, "blocked", false);
        Map<String, Object> tampered = Map.of("userId", 2L, "blocked", false);

        String signature = service.sign(payload);

        assertFalse(service.verify(tampered, signature));
    }

    @Test
    void unsupportedAlgorithmRaisesCryptoException() {
        SignatureService service = buildService("NoSuchAlgorithm-12345");
        SignatureException ex = org.junit.jupiter.api.Assertions.assertThrows(
                SignatureException.class,
                () -> service.sign(Map.of("x", 1)));
        org.junit.jupiter.api.Assertions.assertEquals(
                SignatureException.Category.CRYPTO, ex.getCategory());
    }
}
