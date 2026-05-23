package com.antivirus.binary;

import com.antivirus.malware.SignatureStatus;

/**
 * Маппинг доменного {@link SignatureStatus} в бинарный код для манифеста.
 *
 * <p>Коды:</p>
 * <ul>
 *     <li>{@code 0} — {@link SignatureStatus#ACTUAL};</li>
 *     <li>{@code 1} — {@link SignatureStatus#DELETED}.</li>
 * </ul>
 */
public final class StatusCodeMapper {

    public static final byte ACTUAL_CODE = 0;
    public static final byte DELETED_CODE = 1;

    private StatusCodeMapper() {
    }

    public static byte toCode(SignatureStatus status) {
        return switch (status) {
            case ACTUAL -> ACTUAL_CODE;
            case DELETED -> DELETED_CODE;
        };
    }

    public static SignatureStatus fromCode(byte code) {
        return switch (code) {
            case ACTUAL_CODE -> SignatureStatus.ACTUAL;
            case DELETED_CODE -> SignatureStatus.DELETED;
            default -> throw new IllegalArgumentException("Unknown signature status code: " + code);
        };
    }
}
