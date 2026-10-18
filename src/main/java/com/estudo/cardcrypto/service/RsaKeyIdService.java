package com.estudo.cardcrypto.service;

import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Objects;

@Service
public class RsaKeyIdService {

    public String generateKeyId(PublicKey publicKey)
            throws NoSuchAlgorithmException {

        Objects.requireNonNull(
                publicKey,
                "A chave pública é obrigatória"
        );

        MessageDigest digest =
                MessageDigest.getInstance("SHA-256");

        byte[] hash = digest.digest(
                publicKey.getEncoded()
        );

        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(hash);
    }
}
