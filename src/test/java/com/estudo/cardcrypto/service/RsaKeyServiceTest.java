package com.estudo.cardcrypto.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class RsaKeyServiceTest {

    private RsaKeyService rsaKeyService;

    @BeforeEach
    void setUp() throws Exception {
        rsaKeyService = new RsaKeyService();
    }

    @Test
    void deveGerarChavesPublicaEPrivada() throws Exception {

        RsaKeyService service = new RsaKeyService();

        var publicKey = service.getPublicKey();
        var privateKey = service.getPrivateKey();

        assertNotNull(publicKey);
        assertNotNull(privateKey);

        assertEquals("RSA", publicKey.getAlgorithm());
        assertEquals("RSA", privateKey.getAlgorithm());
    }


    @Test
    void deveRetornarChavePublicaEmBase64() {

        String publicKeyBase64 =
                rsaKeyService.getPublicKeyBase64();

        assertNotNull(publicKeyBase64);
        assertFalse(publicKeyBase64.isBlank());

        byte[] chaveDecodificada =
                Base64.getDecoder().decode(publicKeyBase64);

        assertArrayEquals(
                rsaKeyService.getPublicKey().getEncoded(),
                chaveDecodificada
        );
    }

}