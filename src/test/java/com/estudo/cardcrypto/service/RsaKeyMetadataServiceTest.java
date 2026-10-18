
package com.estudo.cardcrypto.service;

import com.estudo.cardcrypto.entity.RsaKeyEntity;
import com.estudo.cardcrypto.repository.RsaKeyRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class RsaKeyMetadataServiceTest {

    private RsaKeyRepository rsaKeyRepository;
    private RsaKeyMetadataService metadataService;

    @BeforeEach
    void setUp() {
        rsaKeyRepository = mock(RsaKeyRepository.class);

        metadataService = new RsaKeyMetadataService(
                rsaKeyRepository
        );
    }

    @Test
    void deveSalvarMetadadosDaChave() {

        String kid = "rsa-key-teste-001";
        String algorithm = "RSA";

        RsaKeyEntity entidadeSalva =
                new RsaKeyEntity(kid, algorithm);

        when(rsaKeyRepository.save(any(RsaKeyEntity.class)))
                .thenReturn(entidadeSalva);

        RsaKeyEntity resultado =
                metadataService.salvar(kid, algorithm);

        assertNotNull(resultado);
        assertEquals(kid, resultado.getKid());
        assertEquals(algorithm, resultado.getAlgorithm());

        verify(rsaKeyRepository, times(1))
                .save(any(RsaKeyEntity.class));
    }


    @Test
    void deveBuscarMetadadosPeloKid() {

        String kid = "rsa-key-teste-001";

        RsaKeyEntity entidade = new RsaKeyEntity(
                kid,
                "RSA"
        );

        when(rsaKeyRepository.findByKid(kid))
                .thenReturn(Optional.of(entidade));

        Optional<RsaKeyEntity> resultado =
                metadataService.buscarPorKid(kid);

        assertTrue(resultado.isPresent());
        assertEquals(kid, resultado.get().getKid());
        assertEquals("RSA", resultado.get().getAlgorithm());

        verify(rsaKeyRepository, times(1))
                .findByKid(kid);
    }


    @Test
    void deveRetornarOptionalVazioQuandoKidNaoExistir() {

        String kid = "rsa-key-inexistente";

        when(rsaKeyRepository.findByKid(kid))
                .thenReturn(Optional.empty());

        Optional<RsaKeyEntity> resultado =
                metadataService.buscarPorKid(kid);

        assertTrue(resultado.isEmpty());

        verify(rsaKeyRepository, times(1))
                .findByKid(kid);
    }

}
