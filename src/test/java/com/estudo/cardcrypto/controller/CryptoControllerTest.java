package com.estudo.cardcrypto.controller;

import com.estudo.cardcrypto.service.RsaCryptoService;
import com.estudo.cardcrypto.service.RsaKeyService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(CryptoController.class)
@AutoConfigureMockMvc(addFilters = false)
class CryptoControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private RsaCryptoService rsaCryptoService;

    @MockitoBean
    private RsaKeyService rsaKeyService;

    @Test
    void deveCriptografarIdpComSucesso() throws Exception {

        when(rsaCryptoService.encrypt(anyString()))
                .thenReturn("IDP_CRIPTOGRAFADO");

        mockMvc.perform(post("/api/crypto/rsa/encrypt")
                        .contentType("application/json")
                        .content("""
                                {
                                    "value": "IDP123ABC"
                                }
                                """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.result")
                        .value("IDP_CRIPTOGRAFADO"));
    }


    @Test
    void deveDescriptografarIdpComSucesso() throws Exception {

        // Arrange: prepara o comportamento do Service simulado
        when(rsaCryptoService.decrypt("IDP_CRIPTOGRAFADO"))
                .thenReturn("IDP123ABC");

        // Act e Assert: executa a requisição e verifica a resposta
        mockMvc.perform(post("/api/crypto/rsa/decrypt")
                        .contentType("application/json")
                        .content("""
                            {
                                "value": "IDP_CRIPTOGRAFADO"
                            }
                            """))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.result")
                        .value("IDP123ABC"));
    }



    @Test
    void naoDeveCriptografarQuandoValueEstiverVazio() throws Exception {

        mockMvc.perform(post("/api/crypto/rsa/encrypt")
                        .contentType("application/json")
                        .content("""
                            {
                                "value": ""
                            }
                            """))
                .andExpect(status().isBadRequest());

        verifyNoInteractions(rsaCryptoService);
    }


    @Test
    void naoDeveCriptografarQuandoValueForNulo() throws Exception {

        mockMvc.perform(post("/api/crypto/rsa/encrypt")
                        .contentType("application/json")
                        .content("""
                            {
                                "value": null
                            }
                            """))
                .andExpect(status().isBadRequest());

        verifyNoInteractions(rsaCryptoService);
    }


    @Test
    void naoDeveCriptografarQuandoValueNaoForInformado() throws Exception {

        mockMvc.perform(post("/api/crypto/rsa/encrypt")
                        .contentType("application/json")
                        .content("""
                            {
                            }
                            """))
                .andExpect(status().isBadRequest());

        verifyNoInteractions(rsaCryptoService);
    }


    @Test
    void deveRetornarChavePublicaComSucesso()
            throws Exception {

        String chavePublicaBase64 = "CHAVE_PUBLICA_SIMULADA";

        when(rsaKeyService.getPublicKeyBase64())
                .thenReturn(chavePublicaBase64);

        mockMvc.perform(get("/api/crypto/rsa/public-key"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.algorithm").value("RSA"))
                .andExpect(jsonPath("$.publicKey")
                        .value(chavePublicaBase64));

        verify(rsaKeyService).getPublicKeyBase64();
    }


}