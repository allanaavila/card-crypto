
package com.estudo.cardcrypto.integration;

import com.estudo.cardcrypto.entity.RsaKeyEntity;
import com.estudo.cardcrypto.repository.RsaKeyRepository;
import com.estudo.cardcrypto.service.RsaKeyService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@ActiveProfiles({"dev", "test"})
class RsaKeyStartupIntegrationTest {

    @Autowired
    private RsaKeyService rsaKeyService;

    @Autowired
    private RsaKeyRepository rsaKeyRepository;

    @Test
    void deveRegistrarMetadadosDaChaveAtualNoBanco() {

        String kidAtual = rsaKeyService.getKeyId();

        Optional<RsaKeyEntity> resultado =
                rsaKeyRepository.findByKid(kidAtual);

        assertTrue(resultado.isPresent());

        RsaKeyEntity entidade = resultado.get();

        assertEquals(kidAtual, entidade.getKid());
        assertEquals("RSA", entidade.getAlgorithm());
    }
}
