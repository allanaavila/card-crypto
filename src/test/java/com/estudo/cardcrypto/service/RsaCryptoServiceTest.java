package com.estudo.cardcrypto.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class RsaCryptoServiceTest {

    private RsaCryptoService rsaCryptoService;

    @BeforeEach
    void setUp() throws Exception {
        RsaKeyService rsaKeyService = new RsaKeyService();
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
}