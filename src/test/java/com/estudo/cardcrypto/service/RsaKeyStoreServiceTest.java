
package com.estudo.cardcrypto.service;

import com.estudo.cardcrypto.config.RsaKeyStoreProperties;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;

import static org.junit.jupiter.api.Assertions.*;

class RsaKeyStoreServiceTest {

    @TempDir
    Path tempDir;

    @Test
    void deveRetornarFalseQuandoKeyStoreNaoExiste() {

        Path keyStorePath = tempDir.resolve("cardcrypto.p12");

        RsaKeyStoreProperties properties =
                new RsaKeyStoreProperties(
                        keyStorePath.toString(),
                        "senha-de-teste",
                        "cardcrypto-rsa"
                );

        RsaKeyStoreService service =
                new RsaKeyStoreService(properties);

        assertFalse(service.keyStoreExists());
    }


    @Test
    void deveRetornarTrueQuandoKeyStoreExiste() throws Exception {

        Path keyStorePath = tempDir.resolve("cardcrypto.p12");

        Files.createFile(keyStorePath);

        RsaKeyStoreProperties properties =
                new RsaKeyStoreProperties(
                        keyStorePath.toString(),
                        "senha-de-teste",
                        "cardcrypto-rsa"
                );

        RsaKeyStoreService service =
                new RsaKeyStoreService(properties);

        assertTrue(service.keyStoreExists());
    }


    @Test
    void deveCriarKeyStorePkcs12Valido() throws Exception {

        Path keyStorePath = tempDir.resolve("cardcrypto.p12");

        RsaKeyStoreProperties properties =
                new RsaKeyStoreProperties(
                        keyStorePath.toString(),
                        "senha-de-teste",
                        "cardcrypto-rsa"
                );

        RsaKeyStoreService service =
                new RsaKeyStoreService(properties);

        service.createKeyStore();

        assertTrue(Files.isRegularFile(keyStorePath));

        KeyStore keyStore = KeyStore.getInstance("PKCS12");

        try (InputStream input = Files.newInputStream(keyStorePath)) {
            keyStore.load(
                    input,
                    "senha-de-teste".toCharArray()
            );
        }

        assertEquals(0, keyStore.size());
    }


    @Test
    void deveCarregarKeyStoreExistente() throws Exception {

        Path keyStorePath = tempDir.resolve("cardcrypto.p12");

        RsaKeyStoreProperties properties =
                new RsaKeyStoreProperties(
                        keyStorePath.toString(),
                        "senha-de-teste",
                        "cardcrypto-rsa"
                );

        RsaKeyStoreService service =
                new RsaKeyStoreService(properties);

        service.createKeyStore();

        KeyStore keyStore = service.loadKeyStore();

        assertNotNull(keyStore);
        assertEquals("PKCS12", keyStore.getType());
        assertEquals(0, keyStore.size());
    }


    @Test
    void deveFalharAoCarregarKeyStoreComSenhaIncorreta()
            throws Exception {

        Path keyStorePath = tempDir.resolve("cardcrypto.p12");

        RsaKeyStoreProperties propriedadesCorretas =
                new RsaKeyStoreProperties(
                        keyStorePath.toString(),
                        "senha-correta",
                        "cardcrypto-rsa"
                );

        RsaKeyStoreService servicoCriacao =
                new RsaKeyStoreService(propriedadesCorretas);

        servicoCriacao.createKeyStore();

        RsaKeyStoreProperties propriedadesIncorretas =
                new RsaKeyStoreProperties(
                        keyStorePath.toString(),
                        "senha-incorreta",
                        "cardcrypto-rsa"
                );

        RsaKeyStoreService servicoLeitura =
                new RsaKeyStoreService(propriedadesIncorretas);

        assertThrows(
                IOException.class,
                servicoLeitura::loadKeyStore
        );
    }


    @Test
    void deveFalharAoCarregarKeyStoreInexistente() {

        Path keyStorePath = tempDir.resolve("inexistente.p12");

        RsaKeyStoreProperties properties =
                new RsaKeyStoreProperties(
                        keyStorePath.toString(),
                        "senha-de-teste",
                        "cardcrypto-rsa"
                );

        RsaKeyStoreService service =
                new RsaKeyStoreService(properties);

        IOException exception = assertThrows(
                IOException.class,
                service::loadKeyStore
        );

        assertTrue(
                exception.getMessage()
                        .contains("Arquivo KeyStore não encontrado")
        );
    }
}
