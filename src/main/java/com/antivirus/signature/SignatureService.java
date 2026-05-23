package com.antivirus.signature;

import org.springframework.stereotype.Service;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

/**
 * Фасад модуля ЭЦП.
 *
 * <p>Собирает pipeline: канонизация payload (через {@link JsonCanonicalizer}) ->
 * получение приватного ключа (через {@link SignatureKeyProvider}) -> вычисление подписи
 * (через {@link java.security.Signature} с алгоритмом из {@link SignatureProperties#getAlgorithm()}) ->
 * кодирование результата в Base64.</p>
 *
 * <p>Не отвечает за чтение ключей и канонизацию: эти этапы вынесены в отдельные
 * компоненты согласно требованиям методички.</p>
 */
@Service
public class SignatureService {

    private final SignatureKeyProvider keyProvider;
    private final JsonCanonicalizer canonicalizer;
    private final SignatureProperties properties;

    public SignatureService(SignatureKeyProvider keyProvider,
                            JsonCanonicalizer canonicalizer,
                            SignatureProperties properties) {
        this.keyProvider = keyProvider;
        this.canonicalizer = canonicalizer;
        this.properties = properties;
    }

    /**
     * Подписывает произвольный payload. Возвращает строку Base64 с подписью канонизованного
     * представления JSON.
     */
    public String sign(Object payload) {
        byte[] canonicalBytes = canonicalizer.canonicalize(payload);
        byte[] signatureBytes = computeSignature(canonicalBytes);
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    /**
     * Проверяет подпись внешним публичным ключом. Полезно для интеграционных тестов и
     * клиентов, которые принимают тот же сертификат.
     */
    public boolean verify(Object payload, String base64Signature, PublicKey publicKey) {
        byte[] canonicalBytes = canonicalizer.canonicalize(payload);
        byte[] signatureBytes;
        try {
            signatureBytes = Base64.getDecoder().decode(base64Signature);
        } catch (IllegalArgumentException e) {
            throw new SignatureException(SignatureException.Category.CRYPTO,
                    "Invalid Base64 signature", e);
        }
        try {
            Signature sig = Signature.getInstance(properties.getAlgorithm());
            sig.initVerify(publicKey);
            sig.update(canonicalBytes);
            return sig.verify(signatureBytes);
        } catch (GeneralSecurityException e) {
            throw new SignatureException(SignatureException.Category.CRYPTO,
                    "Failed to verify signature", e);
        }
    }

    /**
     * Проверяет подпись публичным ключом из настроенного keystore.
     */
    public boolean verify(Object payload, String base64Signature) {
        return verify(payload, base64Signature, keyProvider.getPublicKey());
    }

    /**
     * Подписывает уже сформированный массив байт без канонизации.
     *
     * <p>Используется для бинарных документов (например, манифеста binary API), которые
     * представляют собой готовый набор байт и не должны повторно превращаться в
     * объектную форму. Возвращает сырые байты подписи (RSA), без Base64.</p>
     */
    public byte[] signBytes(byte[] payload) {
        if (payload == null) {
            throw new SignatureException(SignatureException.Category.CRYPTO,
                    "Payload to sign must not be null");
        }
        return computeSignature(payload);
    }

    /**
     * Проверяет подпись готового массива байт переданным публичным ключом.
     */
    public boolean verifyBytes(byte[] payload, byte[] signatureBytes, PublicKey publicKey) {
        if (payload == null || signatureBytes == null) {
            throw new SignatureException(SignatureException.Category.CRYPTO,
                    "Payload and signature must not be null");
        }
        try {
            Signature sig = Signature.getInstance(properties.getAlgorithm());
            sig.initVerify(publicKey);
            sig.update(payload);
            return sig.verify(signatureBytes);
        } catch (GeneralSecurityException e) {
            throw new SignatureException(SignatureException.Category.CRYPTO,
                    "Failed to verify byte-array signature", e);
        }
    }

    /**
     * Проверяет подпись массива байт публичным ключом из настроенного keystore.
     */
    public boolean verifyBytes(byte[] payload, byte[] signatureBytes) {
        return verifyBytes(payload, signatureBytes, keyProvider.getPublicKey());
    }

    private byte[] computeSignature(byte[] canonicalBytes) {
        try {
            Signature sig = Signature.getInstance(properties.getAlgorithm());
            sig.initSign(keyProvider.getPrivateKey());
            sig.update(canonicalBytes);
            return sig.sign();
        } catch (GeneralSecurityException e) {
            throw new SignatureException(SignatureException.Category.CRYPTO,
                    "Failed to compute signature with algorithm " + properties.getAlgorithm(), e);
        }
    }
}
