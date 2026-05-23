package com.antivirus.binary;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Конфигурация бинарного протокола выгрузки сигнатур.
 *
 * <p>Параметры маппятся из {@code application.yml} (префикс {@code binary}).
 * {@link #surname} участвует в magic-полях ({@code MF-<surname>} и {@code DB-<surname>}),
 * по которым клиент идентифицирует тип файла.</p>
 */
@ConfigurationProperties(prefix = "binary")
public class BinaryProtocolProperties {

    private String surname = "Polyatykin";
    private int manifestVersion = 1;
    private int dataVersion = 1;

    public String getSurname() {
        return surname;
    }

    public void setSurname(String surname) {
        this.surname = surname;
    }

    public int getManifestVersion() {
        return manifestVersion;
    }

    public void setManifestVersion(int manifestVersion) {
        this.manifestVersion = manifestVersion;
    }

    public int getDataVersion() {
        return dataVersion;
    }

    public void setDataVersion(int dataVersion) {
        this.dataVersion = dataVersion;
    }

    public String manifestMagic() {
        return "MF-" + surname;
    }

    public String dataMagic() {
        return "DB-" + surname;
    }
}
