package com.antivirus;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class AntivirusApplication {

    public static void main(String[] args) {
        SpringApplication.run(AntivirusApplication.class, args);
    }
}
