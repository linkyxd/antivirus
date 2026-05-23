package com.antivirus.signature;

/**
 * Ошибка модуля электронной цифровой подписи.
 *
 * <p>Разделяет причины сбоя на категории, чтобы вызывающий код мог отличить ошибки
 * конфигурации (нет такого keystore/alias), ошибки доступа к ресурсам (I/O) и собственно
 * криптографические сбои (несовместимый алгоритм, повреждённый ключ).</p>
 */
public class SignatureException extends RuntimeException {

    public enum Category {
        /** Неверная или отсутствующая конфигурация (пути, alias, пароли). */
        CONFIGURATION,
        /** Ошибка чтения keystore или иного ресурса. */
        IO,
        /** Криптографическая ошибка (алгоритм, инициализация, подпись). */
        CRYPTO
    }

    private final Category category;

    public SignatureException(Category category, String message) {
        super(message);
        this.category = category;
    }

    public SignatureException(Category category, String message, Throwable cause) {
        super(message, cause);
        this.category = category;
    }

    public Category getCategory() {
        return category;
    }
}
