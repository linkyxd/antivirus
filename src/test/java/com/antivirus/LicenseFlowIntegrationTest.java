package com.antivirus;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "TLS_ENABLED=false",
        "DB_URL=jdbc:h2:mem:licensedb;MODE=PostgreSQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE",
        "DB_USERNAME=sa",
        "DB_PASSWORD=",
        "DB_DRIVER_CLASS_NAME=org.h2.Driver",
        "spring.jpa.hibernate.ddl-auto=validate",
        "server.ssl.key-store=classpath:test-keystore.p12",
        "server.ssl.key-store-password=changeit",
        "server.ssl.key-alias=server"
})
class LicenseFlowIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void fullLicenseLifecycle() throws Exception {
        // 1. Регистрируем обычного пользователя
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username": "lic_user", "password": "Pass12345"}
                                """))
                .andExpect(status().isCreated());

        // 2. Логинимся как админ (создаётся в DataInitializer)
        MvcResult adminLogin = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username": "admin", "password": "admin12345"}
                                """))
                .andExpect(status().isOk())
                .andReturn();

        String adminAccess = objectMapper.readTree(adminLogin.getResponse().getContentAsString())
                .get("accessToken").asText();

        // 3. Логинимся как обычный пользователь
        MvcResult userLogin = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username": "lic_user", "password": "Pass12345"}
                                """))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode userLoginJson = objectMapper.readTree(userLogin.getResponse().getContentAsString());
        String userAccess = userLoginJson.get("accessToken").asText();

        // 4. Сначала проверяем отрицательные сценарии создания лицензии.

        // 4a. Пытаемся создать лицензию без существующего продукта — ожидаем 404
        mockMvc.perform(post("/api/licenses")
                        .header("Authorization", "Bearer " + adminAccess)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"productId": 999, "typeId": 1, "ownerId": 1, "deviceCount": 2, "description": "test"}
                                """))
                .andExpect(status().isNotFound());

        // 4b. Обычный пользователь пытается создать лицензию — ожидаем 403
        mockMvc.perform(post("/api/licenses")
                        .header("Authorization", "Bearer " + userAccess)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"productId": 1, "typeId": 1, "ownerId": 1, "deviceCount": 1, "description": "test"}
                                """))
                .andExpect(status().isForbidden());
    }

    @Test
    void activateCheckRenewWithSeededData() throws Exception {
        // Регистрируем и логиним пользователя
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username": "lic_user2", "password": "Pass12345"}
                                """))
                .andExpect(status().isCreated());

        MvcResult adminLogin = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username": "admin", "password": "admin12345"}
                                """))
                .andExpect(status().isOk())
                .andReturn();
        String adminAccess = objectMapper.readTree(adminLogin.getResponse().getContentAsString())
                .get("accessToken").asText();

        MvcResult userLogin = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"username": "lic_user2", "password": "Pass12345"}
                                """))
                .andExpect(status().isOk())
                .andReturn();
        String userAccess = objectMapper.readTree(userLogin.getResponse().getContentAsString())
                .get("accessToken").asText();

        // Подготавливаем product и license_type через репозитории
        seedProductAndType();

        // Админ создаёт лицензию
        MvcResult createResult = mockMvc.perform(post("/api/licenses")
                        .header("Authorization", "Bearer " + adminAccess)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"productId": 1, "typeId": 1, "ownerId": 1, "deviceCount": 3, "description": "Test license"}
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.code").isNotEmpty())
                .andReturn();

        String licenseCode = objectMapper.readTree(createResult.getResponse().getContentAsString())
                .get("code").asText();

        // Пользователь активирует лицензию
        MvcResult activateResult = mockMvc.perform(post("/api/licenses/activate")
                        .header("Authorization", "Bearer " + userAccess)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(String.format("""
                                {"activationKey": "%s", "deviceMac": "AA:BB:CC:DD:EE:01", "deviceName": "TestPC"}
                                """, licenseCode)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ticket").exists())
                .andExpect(jsonPath("$.digitalSignature").isNotEmpty())
                .andReturn();

        JsonNode ticketNode = objectMapper.readTree(activateResult.getResponse().getContentAsString())
                .get("ticket");
        assertNotNull(ticketNode.get("activationDate").asText());
        assertNotNull(ticketNode.get("expirationDate").asText());

        // Пользователь проверяет лицензию
        mockMvc.perform(post("/api/licenses/check")
                        .header("Authorization", "Bearer " + userAccess)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"productId": 1, "deviceMac": "AA:BB:CC:DD:EE:01"}
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ticket.blocked").value(false))
                .andExpect(jsonPath("$.digitalSignature").isNotEmpty());

        // Продление должно вернуть ошибку — срок ещё не близок к окончанию
        mockMvc.perform(post("/api/licenses/renew")
                        .header("Authorization", "Bearer " + userAccess)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(String.format("""
                                {"activationKey": "%s"}
                                """, licenseCode)))
                .andExpect(status().isBadRequest());
    }

    @Autowired
    private com.antivirus.product.ProductRepository productRepository;

    @Autowired
    private com.antivirus.license.LicenseTypeRepository licenseTypeRepository;

    private void seedProductAndType() {
        if (productRepository.count() == 0) {
            var product = new com.antivirus.product.ProductEntity();
            product.setName("Antivirus Pro");
            productRepository.save(product);
        }
        if (licenseTypeRepository.count() == 0) {
            var type = new com.antivirus.license.LicenseTypeEntity();
            type.setName("ANNUAL");
            type.setDefaultDurationInDays(365);
            type.setDescription("Annual license");
            licenseTypeRepository.save(type);
        }
    }
}
