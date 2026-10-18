
package com.estudo.cardcrypto.service;

import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;

import static org.junit.jupiter.api.Assertions.*;

class RsaCertificateServiceTest {

    @Test
    void deveGerarCertificadoAutoassinado()
            throws Exception {

        KeyPairGenerator generator =
                KeyPairGenerator.getInstance("RSA");

        generator.initialize(2048);

        KeyPair keyPair = generator.generateKeyPair();

        RsaCertificateService service =
                new RsaCertificateService();

        X509Certificate certificate =
                service.generateSelfSignedCertificate(keyPair);

        assertNotNull(certificate);

        assertEquals(
                "X.509",
                certificate.getType()
        );

        assertArrayEquals(
                keyPair.getPublic().getEncoded(),
                certificate.getPublicKey().getEncoded()
        );

        certificate.checkValidity();

        certificate.verify(keyPair.getPublic());
    }
}
