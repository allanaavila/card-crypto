
package com.estudo.cardcrypto.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles({"dev", "test"})
class RsaKeyStorePropertiesTest {

    @Autowired
    private RsaKeyStoreProperties properties;

    @Test
    void deveCarregarConfiguracoesDoKeyStore() {
        assertEquals(
                "./data/keys/cardcrypto.p12",
                properties.path()
        );

        assertEquals(
                "cardcrypto-rsa",
                properties.alias()
        );

        assertNotNull(properties.password());
        assertFalse(properties.password().isBlank());
    }
}
