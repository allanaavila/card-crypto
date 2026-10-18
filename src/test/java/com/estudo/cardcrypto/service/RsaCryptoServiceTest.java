package com.estudo.cardcrypto.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import java.security.spec.MGF1ParameterSpec;

import static org.junit.jupiter.api.Assertions.*;

class RsaCryptoServiceTest {

    private RsaKeyService rsaKeyService;
    private RsaCryptoService rsaCryptoService;


    @BeforeEach
    void setUp() throws Exception {
        rsaKeyService = new RsaKeyService();
        rsaCryptoService = new RsaCryptoService(rsaKeyService);
    }

    @Test
    void deveCriptografarIdpComRsa() throws Exception {
        String idp = "IPD123ABC";

        String encrypted = rsaCryptoService.encrypt(idp);

        assertNotNull(encrypted);
        assertNotEquals(idp, encrypted);
        assertFalse(encrypted.isBlank());

        byte[] decoded = Base64.getDecoder().decode(encrypted);
        assertTrue(decoded.length > 0);
    }

    @Test
    void naoDeveCriptografarTextoVazio() {
        assertThrows(IllegalArgumentException.class, () ->
            rsaCryptoService.encrypt("")
        );
    }

    @Test
    void naoDeveCriptografarTextoNulo() {
        assertThrows(IllegalArgumentException.class, () ->
            rsaCryptoService.encrypt(null)
        );
    }

    @Test
    void deveCriptografarEDescriptografarIdp() throws Exception {

        String idpOriginal = "IDP123ABC";

        String textoCriptografado =
                rsaCryptoService.encrypt(idpOriginal);

        String textoDescriptografado =
                rsaCryptoService.decrypt(textoCriptografado);

        assertNotEquals(idpOriginal, textoCriptografado);
        assertEquals(idpOriginal, textoDescriptografado);
    }

    @Test
    void naoDeveDescriptografarTextoVazio() {

        assertThrows(
                IllegalArgumentException.class,
                () -> rsaCryptoService.decrypt("")
        );
    }

    @Test
    void naoDeveDescriptografarBase64Invalido() {

        String textoInvalido = "###NAO_E_BASE64###";

        assertThrows(
                IllegalArgumentException.class,
                () -> rsaCryptoService.decrypt(textoInvalido)
        );
    }



    @Test
    void deveUtilizarOaepComSha256EMgf1Sha256()
            throws Exception {

        String idpOriginal = "IDP123ABC";

        String textoCriptografado =
                rsaCryptoService.encrypt(idpOriginal);

        Cipher cipher = Cipher.getInstance(
                "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
        );

        OAEPParameterSpec parametros = new OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                javax.crypto.spec.PSource.PSpecified.DEFAULT
        );

        cipher.init(
                Cipher.DECRYPT_MODE,
                rsaKeyService.getPrivateKey(),
                parametros
        );

        byte[] bytesCriptografados =
                Base64.getDecoder().decode(textoCriptografado);

        byte[] bytesDescriptografados =
                cipher.doFinal(bytesCriptografados);

        String resultado = new String(
                bytesDescriptografados,
                java.nio.charset.StandardCharsets.UTF_8
        );

        assertEquals(idpOriginal, resultado);
    }


    @Test
    void deveDescriptografarComOaepSha256EMgf1Sha256()
            throws Exception {

        String idpOriginal = "IDP123ABC";

        OAEPParameterSpec parametros = new OAEPParameterSpec(
                "SHA-256",
                "MGF1",
                MGF1ParameterSpec.SHA256,
                javax.crypto.spec.PSource.PSpecified.DEFAULT
        );

        Cipher cipher = Cipher.getInstance(
                "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
        );

        cipher.init(
                Cipher.ENCRYPT_MODE,
                rsaKeyService.getPublicKey(),
                parametros
        );

        byte[] bytesCriptografados = cipher.doFinal(
                idpOriginal.getBytes(
                        java.nio.charset.StandardCharsets.UTF_8
                )
        );

        String textoCriptografado = Base64.getEncoder()
                .encodeToString(bytesCriptografados);

        String resultado = rsaCryptoService.decrypt(
                textoCriptografado
        );

        assertEquals(idpOriginal, resultado);
    }

}