package com.antivirus.binary;

/**
 * Тип бинарной выгрузки. Кодируется в манифест как один байт ({@code uint8}).
 *
 * <ul>
 *     <li>{@link #FULL} — полная база, только {@code ACTUAL};</li>
 *     <li>{@link #INCREMENT} — все записи с {@code updatedAt > since}, включая {@code DELETED};</li>
 *     <li>{@link #BY_IDS} — выборка по списку идентификаторов.</li>
 * </ul>
 */
public enum ExportType {
    FULL((byte) 0),
    INCREMENT((byte) 1),
    BY_IDS((byte) 2);

    private final byte code;

    ExportType(byte code) {
        this.code = code;
    }

    public byte code() {
        return code;
    }
}
