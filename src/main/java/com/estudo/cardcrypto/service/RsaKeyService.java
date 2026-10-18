
package com.estudo.cardcrypto.service;

import lombok.Getter;
import org.springframework.stereotype.Service;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Objects;
import java.util.UUID;

@Service
public class RsaKeyService {

    private final KeyPair keyPair;

    @Getter
    private final String keyId;

    // Construtor utilizado pelo Spring
    public RsaKeyService() throws GeneralSecurityException {
        this.keyPair = generateKeyPair();
        this.keyId = UUID.randomUUID().toString();
    }

    // Construtor para utilizar chaves já existentes
    public RsaKeyService(KeyPair keyPair, String keyId) {
        this.keyPair = Objects.requireNonNull(
                keyPair,
                "O par de chaves RSA é obrigatório"
        );

        this.keyId = Objects.requireNonNull(
                keyId,
                "O identificador da chave é obrigatório"
        );
    }

    // Gera um novo par de chaves RSA
    private KeyPair generateKeyPair()
            throws GeneralSecurityException {

        KeyPairGenerator generator =
                KeyPairGenerator.getInstance("RSA");

        generator.initialize(2048);

        return generator.generateKeyPair();
    }

    // Retorna a chave pública em Base64
    public String getPublicKeyBase64() {
        byte[] publicKeyBytes = getPublicKey().getEncoded();

        return Base64.getEncoder()
                .encodeToString(publicKeyBytes);
    }

    // Retorna a chave pública
    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    // Retorna a chave privada
    public PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }
}
