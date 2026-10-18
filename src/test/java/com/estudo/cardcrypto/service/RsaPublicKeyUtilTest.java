
package com.estudo.cardcrypto.service;

import org.junit.jupiter.api.Test;
import java.security.PublicKey;
import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.spec.MGF1ParameterSpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class RsaPublicKeyUtilTest {

    @Test
    void deveReconstruirChavePublicaAPartirDoBase64()
            throws Exception {

        RsaKeyService rsaKeyService = new RsaKeyService();

        PublicKey chavePublicaOriginal =
                rsaKeyService.getPublicKey();

        String chavePublicaBase64 =
                rsaKeyService.getPublicKeyBase64();

        PublicKey chavePublicaReconstruida =
                RsaPublicKeyUtil.fromBase64(chavePublicaBase64);

        assertNotNull(chavePublicaReconstruida);

        assertEquals(
                "RSA",
                chavePublicaReconstruida.getAlgorithm()
        );

        assertArrayEquals(
                chavePublicaOriginal.getEncoded(),
                chavePublicaReconstruida.getEncoded()
        );
    }


    @Test
    void deveCriptografarComChavePublicaReconstruida()
            throws Exception {

        RsaKeyService rsaKeyService = new RsaKeyService();
        RsaCryptoService rsaCryptoService =
                new RsaCryptoService(rsaKeyService);

        String idpOriginal = "IDP123ABC";

        String chavePublicaBase64 =
                rsaKeyService.getPublicKeyBase64();

        PublicKey chavePublicaCliente =
                RsaPublicKeyUtil.fromBase64(chavePublicaBase64);

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
                chavePublicaCliente,
                parametros
        );

        byte[] bytesCriptografados = cipher.doFinal(
                idpOriginal.getBytes(StandardCharsets.UTF_8)
        );

        String textoCriptografado = Base64.getEncoder()
                .encodeToString(bytesCriptografados);

        String resultado =
                rsaCryptoService.decrypt(textoCriptografado);

        assertEquals(idpOriginal, resultado);
    }

}
