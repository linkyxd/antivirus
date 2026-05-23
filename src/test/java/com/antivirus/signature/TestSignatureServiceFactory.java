package com.antivirus.signature;

import java.security.KeyPair;

/**
 * Тестовая фабрика {@link SignatureService} с in-memory ключами.
 *
 * <p>Существует, потому что test-конструктор {@link SignatureKeyProvider} имеет
 * package-private видимость, а тесты из других пакетов также хотят собрать сервис
 * без обращения к настоящему keystore.</p>
 */
public final class TestSignatureServiceFactory {

    private TestSignatureServiceFactory() {
    }

    public static SignatureService build(KeyPair keyPair, String algorithm) {
        SignatureProperties properties = new SignatureProperties();
        properties.setAlgorithm(algorithm);
        SignatureKeyProvider provider = new SignatureKeyProvider(
                keyPair.getPrivate(), keyPair.getPublic(), null);
        return new SignatureService(provider, new JsonCanonicalizer(), properties);
    }
}
