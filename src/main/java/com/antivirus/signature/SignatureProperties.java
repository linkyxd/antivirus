package com.antivirus.signature;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Конфигурация модуля электронной цифровой подписи.
 *
 * <p>Префикс {@code signature} в application.yml. Описывает доступ к хранилищу ключей и
 * выбранному алгоритму подписи.</p>
 *
 * <p>Поле {@link #keyPassword} опционально: если оно пустое, при чтении приватного ключа
 * используется {@link #keyStorePassword} — так же ведёт себя {@code keytool}, если при
 * генерации не задан отдельный {@code -keypass}.</p>
 */
@ConfigurationProperties(prefix = "signature")
public class SignatureProperties {

    /**
     * Путь к keystore. Поддерживаются {@code classpath:...}, {@code file:...} либо обычный
     * относительный/абсолютный путь файловой системы.
     */
    private String keyStorePath;

    /** Тип хранилища (PKCS12 / JKS). */
    private String keyStoreType = "PKCS12";

    /** Пароль хранилища. */
    private String keyStorePassword;

    /** Alias записи приватного ключа в keystore. */
    private String keyAlias;

    /** Пароль приватного ключа. Если пуст — используется {@link #keyStorePassword}. */
    private String keyPassword;

    /** Алгоритм подписи. По умолчанию SHA256withRSA согласно методичке. */
    private String algorithm = "SHA256withRSA";

    public String getKeyStorePath() {
        return keyStorePath;
    }

    public void setKeyStorePath(String keyStorePath) {
        this.keyStorePath = keyStorePath;
    }

    public String getKeyStoreType() {
        return keyStoreType;
    }

    public void setKeyStoreType(String keyStoreType) {
        this.keyStoreType = keyStoreType;
    }

    public String getKeyStorePassword() {
        return keyStorePassword;
    }

    public void setKeyStorePassword(String keyStorePassword) {
        this.keyStorePassword = keyStorePassword;
    }

    public String getKeyAlias() {
        return keyAlias;
    }

    public void setKeyAlias(String keyAlias) {
        this.keyAlias = keyAlias;
    }

    public String getKeyPassword() {
        return keyPassword;
    }

    public void setKeyPassword(String keyPassword) {
        this.keyPassword = keyPassword;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    /**
     * Возвращает эффективный пароль приватного ключа.
     *
     * @return {@link #keyPassword}, если задан, иначе {@link #keyStorePassword}.
     */
    public String resolveKeyPassword() {
        if (keyPassword == null || keyPassword.isEmpty()) {
            return keyStorePassword;
        }
        return keyPassword;
    }
}
