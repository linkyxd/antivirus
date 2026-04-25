package com.antivirus.ticket;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;

@Service
public class TicketSigningService {

    @Value("${server.ssl.key-store}")
    private String keystorePath;

    @Value("${server.ssl.key-store-password}")
    private String keystorePassword;

    @Value("${server.ssl.key-alias}")
    private String keyAlias;

    private PrivateKey privateKey;
    private final ObjectMapper objectMapper;
    private final ResourceLoader resourceLoader;

    public TicketSigningService() {
        this.objectMapper = new ObjectMapper();
        this.objectMapper.registerModule(new JavaTimeModule());
        this.resourceLoader = new DefaultResourceLoader();
    }

    @PostConstruct
    void loadKey() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream is = resolveKeystoreStream()) {
            keyStore.load(is, keystorePassword.toCharArray());
        }
        this.privateKey = (PrivateKey) keyStore.getKey(keyAlias, keystorePassword.toCharArray());
        if (this.privateKey == null) {
            throw new IllegalStateException("Private key not found for alias: " + keyAlias);
        }
    }

    private InputStream resolveKeystoreStream() throws Exception {
        // Явное указание ресурса Spring (classpath:, file: и т.д.)
        if (keystorePath.contains(":")) {
            Resource resource = resourceLoader.getResource(keystorePath);
            if (resource.exists()) {
                return resource.getInputStream();
            }
        }

        // Обычный относительный/абсолютный путь в файловой системе (например certs/server-keystore.p12)
        File file = new File(keystorePath);
        if (file.exists()) {
            return new FileInputStream(file);
        }

        // Резервный вариант: поиск в classpath для обычных путей
        Resource classpathResource = resourceLoader.getResource("classpath:" + keystorePath);
        if (classpathResource.exists()) {
            return classpathResource.getInputStream();
        }

        throw new IllegalStateException("Keystore not found: " + keystorePath);
    }

    public TicketResponse sign(Ticket ticket) {
        try {
            byte[] ticketBytes = objectMapper.writeValueAsBytes(ticket);
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(privateKey);
            sig.update(ticketBytes);
            String digitalSignature = Base64.getEncoder().encodeToString(sig.sign());
            return new TicketResponse(ticket, digitalSignature);
        } catch (Exception e) {
            throw new RuntimeException("Failed to sign ticket", e);
        }
    }
}
