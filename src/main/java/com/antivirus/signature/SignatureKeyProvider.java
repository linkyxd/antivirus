package com.antivirus.signature;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

/**
 * Компонент Key Provider модуля ЭЦП.
 *
 * <p>Загружает keystore один раз при инициализации Spring-контекста и кеширует
 * пару (приватный ключ, сертификат). Гарантия методички:</p>
 * <ul>
 *     <li>возвращает согласованную пару;</li>
 *     <li>безопасен относительно конкурентных обращений (immutable после старта);</li>
 *     <li>классифицирует ошибки через {@link SignatureException.Category}.</li>
 * </ul>
 *
 * <p>Путь до keystore поддерживает {@code classpath:}, {@code file:} и обычные пути файловой системы.</p>
 */
@Component
public class SignatureKeyProvider {

    private final SignatureProperties properties;
    private final ResourceLoader resourceLoader;

    private volatile PrivateKey privateKey;
    private volatile PublicKey publicKey;
    private volatile Certificate certificate;

    @Autowired
    public SignatureKeyProvider(SignatureProperties properties) {
        this.properties = properties;
        this.resourceLoader = new DefaultResourceLoader();
    }

    /**
     * Тестовый конструктор: позволяет подставить ключи напрямую, минуя загрузку из keystore.
     * Сертификат необязателен.
     */
    SignatureKeyProvider(PrivateKey privateKey, PublicKey publicKey, Certificate certificate) {
        this.properties = null;
        this.resourceLoader = new DefaultResourceLoader();
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.certificate = certificate;
    }

    @PostConstruct
    void load() {
        validateConfig();

        KeyStore keyStore;
        try {
            keyStore = KeyStore.getInstance(properties.getKeyStoreType());
        } catch (GeneralSecurityException e) {
            throw new SignatureException(SignatureException.Category.CONFIGURATION,
                    "Unsupported keystore type: " + properties.getKeyStoreType(), e);
        }

        char[] storePassword = properties.getKeyStorePassword().toCharArray();
        try (InputStream is = openKeystoreStream(properties.getKeyStorePath())) {
            keyStore.load(is, storePassword);
        } catch (IOException e) {
            throw new SignatureException(SignatureException.Category.IO,
                    "Failed to read keystore: " + properties.getKeyStorePath(), e);
        } catch (GeneralSecurityException e) {
            throw new SignatureException(SignatureException.Category.CRYPTO,
                    "Failed to load keystore (wrong password or corrupted): " + properties.getKeyStorePath(), e);
        }

        char[] keyPassword = properties.resolveKeyPassword().toCharArray();
        Key key;
        try {
            key = keyStore.getKey(properties.getKeyAlias(), keyPassword);
        } catch (GeneralSecurityException e) {
            throw new SignatureException(SignatureException.Category.CRYPTO,
                    "Failed to read private key for alias: " + properties.getKeyAlias(), e);
        }
        if (!(key instanceof PrivateKey pk)) {
            throw new SignatureException(SignatureException.Category.CONFIGURATION,
                    "Alias does not refer to a private key entry: " + properties.getKeyAlias());
        }

        Certificate cert;
        try {
            cert = keyStore.getCertificate(properties.getKeyAlias());
        } catch (GeneralSecurityException e) {
            throw new SignatureException(SignatureException.Category.CRYPTO,
                    "Failed to read certificate for alias: " + properties.getKeyAlias(), e);
        }
        if (cert == null) {
            throw new SignatureException(SignatureException.Category.CONFIGURATION,
                    "Certificate not found for alias: " + properties.getKeyAlias());
        }

        this.privateKey = pk;
        this.certificate = cert;
        this.publicKey = cert.getPublicKey();
    }

    private void validateConfig() {
        if (isBlank(properties.getKeyStorePath())) {
            throw new SignatureException(SignatureException.Category.CONFIGURATION,
                    "signature.key-store-path is not configured");
        }
        if (isBlank(properties.getKeyStoreType())) {
            throw new SignatureException(SignatureException.Category.CONFIGURATION,
                    "signature.key-store-type is not configured");
        }
        if (properties.getKeyStorePassword() == null) {
            throw new SignatureException(SignatureException.Category.CONFIGURATION,
                    "signature.key-store-password is not configured");
        }
        if (isBlank(properties.getKeyAlias())) {
            throw new SignatureException(SignatureException.Category.CONFIGURATION,
                    "signature.key-alias is not configured");
        }
    }

    private InputStream openKeystoreStream(String path) throws IOException {
        if (path.contains(":")) {
            Resource resource = resourceLoader.getResource(path);
            if (resource.exists()) {
                return resource.getInputStream();
            }
        }
        File file = new File(path);
        if (file.exists()) {
            return new FileInputStream(file);
        }
        Resource classpathResource = resourceLoader.getResource("classpath:" + path);
        if (classpathResource.exists()) {
            return classpathResource.getInputStream();
        }
        throw new SignatureException(SignatureException.Category.IO,
                "Keystore not found at path: " + path);
    }

    /**
     * Возвращает приватный ключ для подписи. Никогда не {@code null} после инициализации.
     */
    public PrivateKey getPrivateKey() {
        ensureLoaded();
        return privateKey;
    }

    /**
     * Возвращает публичный ключ (для верификации).
     */
    public PublicKey getPublicKey() {
        ensureLoaded();
        return publicKey;
    }

    /**
     * Возвращает сертификат, ассоциированный с alias подписи.
     * Может быть {@code null} в тестовых сценариях, когда задан только публичный ключ.
     */
    public Certificate getCertificate() {
        ensureLoaded();
        return certificate;
    }

    private void ensureLoaded() {
        if (privateKey == null || publicKey == null) {
            throw new SignatureException(SignatureException.Category.CONFIGURATION,
                    "Signature key provider is not initialized");
        }
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}
