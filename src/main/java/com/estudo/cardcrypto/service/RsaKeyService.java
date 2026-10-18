package com.estudo.cardcrypto.service;

import lombok.Getter;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.UUID;

@Service
public class RsaKeyService {
    private final KeyPair keyPair;

    @Getter
    private final String keyId;

    public RsaKeyService() throws Exception {
        KeyPairGenerator generator =
                KeyPairGenerator.getInstance("RSA");

        generator.initialize(2048);

        this.keyPair = generator.generateKeyPair();

        this.keyId = UUID.randomUUID().toString();
    }


    public String getPublicKeyBase64() {
        byte[] publicKeyBytes = getPublicKey().getEncoded();

        return Base64.getEncoder()
                .encodeToString(publicKeyBytes);
    }

    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    public PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }
}
