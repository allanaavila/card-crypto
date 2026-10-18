
package com.estudo.cardcrypto.repository;

import com.estudo.cardcrypto.entity.RsaKeyEntity;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.data.jpa.test.autoconfigure.DataJpaTest;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
class RsaKeyRepositoryTest {

    @Autowired
    private RsaKeyRepository rsaKeyRepository;

    @Test
    void deveSalvarEBuscarChavePeloKid() {

        RsaKeyEntity chave = new RsaKeyEntity(
                "rsa-key-teste-001",
                "RSA"
        );

        rsaKeyRepository.save(chave);

        Optional<RsaKeyEntity> resultado =
                rsaKeyRepository.findByKid("rsa-key-teste-001");

        assertTrue(resultado.isPresent());
        assertEquals(
                "rsa-key-teste-001",
                resultado.get().getKid()
        );
        assertEquals(
                "RSA",
                resultado.get().getAlgorithm()
        );
    }


    @Test
    void deveRetornarOptionalVazioQuandoKidNaoExistir() {

        String kidInexistente = "rsa-key-inexistente";

        Optional<RsaKeyEntity> resultado =
                rsaKeyRepository.findByKid(kidInexistente);

        assertTrue(resultado.isEmpty());
    }
}
