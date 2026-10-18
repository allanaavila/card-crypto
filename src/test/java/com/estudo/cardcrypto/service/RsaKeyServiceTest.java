package com.estudo.cardcrypto.service;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class RsaKeyServiceTest {

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
}