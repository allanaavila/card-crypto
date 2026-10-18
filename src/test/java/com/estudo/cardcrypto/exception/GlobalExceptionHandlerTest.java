
package com.estudo.cardcrypto.exception;

import com.estudo.cardcrypto.controller.CryptoController;
import com.estudo.cardcrypto.service.RsaCryptoService;

import com.estudo.cardcrypto.service.RsaKeyService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.security.GeneralSecurityException;

import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest(CryptoController.class)
@AutoConfigureMockMvc(addFilters = false)
@Import(GlobalExceptionHandler.class)
class GlobalExceptionHandlerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private RsaCryptoService rsaCryptoService;

    @MockitoBean
    private RsaKeyService rsaKeyService;

    @Test
    void deveRetornarMensagemDeErroQuandoValueEstiverVazio()
            throws Exception {

        mockMvc.perform(post("/api/crypto/rsa/encrypt")
                        .contentType("application/json")
                        .content("""
                                {
                                    "value": ""
                                }
                                """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message")
                        .value("O campo value é obrigatório"));

        verifyNoInteractions(rsaCryptoService);
    }


    @Test
    void deveRetornarBadRequestQuandoBase64ForInvalido()
            throws Exception {

        when(rsaCryptoService.decrypt("%%%TEXTO_INVALIDO%%%"))
                .thenThrow(new IllegalArgumentException(
                        "Illegal base64 character"
                ));

        mockMvc.perform(post("/api/crypto/rsa/decrypt")
                        .contentType("application/json")
                        .content("""
                            {
                                "value": "%%%TEXTO_INVALIDO%%%"
                            }
                            """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message")
                        .value("Valor informado inválido"));

        verify(rsaCryptoService)
                .decrypt("%%%TEXTO_INVALIDO%%%");
    }


    @Test
    void deveRetornarBadRequestQuandoDescriptografiaFalhar()
            throws Exception {

        when(rsaCryptoService.decrypt("BASE64_VALIDO_MAS_INVALIDO_PARA_RSA"))
                .thenThrow(new GeneralSecurityException(
                        "Falha na descriptografia"
                ));

        mockMvc.perform(post("/api/crypto/rsa/decrypt")
                        .contentType("application/json")
                        .content("""
                            {
                                "value": "BASE64_VALIDO_MAS_INVALIDO_PARA_RSA"
                            }
                            """))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.message")
                        .value("Não foi possível processar o conteúdo criptografado"));

        verify(rsaCryptoService)
                .decrypt("BASE64_VALIDO_MAS_INVALIDO_PARA_RSA");
    }


}
