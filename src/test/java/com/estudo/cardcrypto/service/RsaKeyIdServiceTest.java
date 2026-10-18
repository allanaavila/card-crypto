
package com.estudo.cardcrypto.service;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;

import static org.junit.jupiter.api.Assertions.*;

class RsaKeyIdServiceTest {

    private final RsaKeyIdService service =
            new RsaKeyIdService();

    @Test
    void deveGerarMesmoKidParaMesmaChavePublica()
            throws Exception {

        KeyPairGenerator generator =
                KeyPairGenerator.getInstance("RSA");

        generator.initialize(2048);

        KeyPair keyPair = generator.generateKeyPair();

        String primeiroKid =
                service.generateKeyId(keyPair.getPublic());

        String segundoKid =
                service.generateKeyId(keyPair.getPublic());

        assertNotNull(primeiroKid);
        assertFalse(primeiroKid.isBlank());

        assertEquals(primeiroKid, segundoKid);
    }

    @Test
    void deveGerarKidsDiferentesParaChavesDiferentes()
            throws Exception {

        KeyPairGenerator generator =
                KeyPairGenerator.getInstance("RSA");

        generator.initialize(2048);

        KeyPair primeiroPar = generator.generateKeyPair();
        KeyPair segundoPar = generator.generateKeyPair();

        String primeiroKid =
                service.generateKeyId(primeiroPar.getPublic());

        String segundoKid =
                service.generateKeyId(segundoPar.getPublic());

        assertNotEquals(primeiroKid, segundoKid);
    }
}
