package com.estudo.cardcrypto.repository;

import com.estudo.cardcrypto.entity.RsaKeyEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RsaKeyRepository
        extends JpaRepository<RsaKeyEntity, Long> {

    Optional<RsaKeyEntity> findByKid(String kid);
}
