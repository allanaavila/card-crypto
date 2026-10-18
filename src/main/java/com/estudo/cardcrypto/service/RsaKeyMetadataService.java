package com.estudo.cardcrypto.service;

import com.estudo.cardcrypto.entity.RsaKeyEntity;
import com.estudo.cardcrypto.repository.RsaKeyRepository;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class RsaKeyMetadataService {

    private final RsaKeyRepository rsaKeyRepository;

    public RsaKeyMetadataService(
            RsaKeyRepository rsaKeyRepository
    ) {
        this.rsaKeyRepository = rsaKeyRepository;
    }

    public RsaKeyEntity salvar(String kid, String algorithm) {

        RsaKeyEntity entity = new RsaKeyEntity(
                kid,
                algorithm
        );

        return rsaKeyRepository.save(entity);
    }

    public Optional<RsaKeyEntity> buscarPorKid(String kid) {
        return rsaKeyRepository.findByKid(kid);
    }
}
