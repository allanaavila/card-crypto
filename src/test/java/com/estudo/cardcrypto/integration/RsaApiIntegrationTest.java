
package com.estudo.cardcrypto.integration;

import com.estudo.cardcrypto.service.RsaPublicKeyUtil;
import tools.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("dev")
class RsaApiIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    void deveConsultarChavePublicaViaHttp()
            throws Exception {

        String responseBody = mockMvc.perform(
                        get("/api/crypto/rsa/public-key")
                )
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        var json = objectMapper.readTree(responseBody);

        assertEquals("RSA", json.get("algorithm").asText());

        String chavePublicaBase64 =
                json.get("publicKey").asText();

        assertNotNull(chavePublicaBase64);
        assertFalse(chavePublicaBase64.isBlank());
    }


    @Test
    void deveCriptografarComChavePublicaEDescriptografarViaHttp()
            throws Exception {

        String responseBody = mockMvc.perform(
                        get("/api/crypto/rsa/public-key")
                )
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        var json = objectMapper.readTree(responseBody);

        String chavePublicaBase64 =
                json.get("publicKey").asText();

        PublicKey chavePublica =
                RsaPublicKeyUtil.fromBase64(chavePublicaBase64);

        String idpOriginal = "IDP123ABC";

        OAEPParameterSpec parametros = new OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                PSource.PSpecified.DEFAULT
        );

        Cipher cipher = Cipher.getInstance(
                "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
        );

        cipher.init(
                Cipher.ENCRYPT_MODE,
                chavePublica,
                parametros
        );

        byte[] bytesCriptografados = cipher.doFinal(
                idpOriginal.getBytes(StandardCharsets.UTF_8)
        );

        String textoCriptografado = Base64.getEncoder()
                .encodeToString(bytesCriptografados);

        String requestBody = objectMapper.writeValueAsString(
                new com.estudo.cardcrypto.dto.CryptoRequest(
                        textoCriptografado
                )
        );

        mockMvc.perform(
                        post("/api/crypto/rsa/decrypt")
                                .contentType("application/json")
                                .content(requestBody)
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.result").value(idpOriginal));
    }

}
