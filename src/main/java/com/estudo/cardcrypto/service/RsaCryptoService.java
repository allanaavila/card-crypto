package com.estudo.cardcrypto.service;

import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;

import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.spec.MGF1ParameterSpec;

@Service
public class RsaCryptoService {

    private final RsaKeyService rsaKeyService;

    public RsaCryptoService(RsaKeyService rsaKeyService) {
        this.rsaKeyService = rsaKeyService;
    }

    public String encrypt(String text) throws GeneralSecurityException {

        if (text == null || text.isBlank()) {
            throw new IllegalArgumentException("O texto não pode ser vazio");
        }
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

        cipher.init(
                Cipher.ENCRYPT_MODE,
                rsaKeyService.getPublicKey(),
                OAEP_SHA256_SPEC
        );

        byte[] textBytes = text.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedBytes = cipher.doFinal(textBytes);

        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String encryptText) throws GeneralSecurityException {

        if(encryptText == null || encryptText.isBlank()) {
            throw new IllegalArgumentException("O texto não pode ser vazio");
        }

        byte[] encryptedBytes = Base64.getDecoder().decode(encryptText);

        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

        cipher.init(
                Cipher.DECRYPT_MODE,
                rsaKeyService.getPrivateKey(),
                OAEP_SHA256_SPEC
        );

        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }


    private static final OAEPParameterSpec OAEP_SHA256_SPEC =
            new OAEPParameterSpec(
                    "SHA-256",
                    "MGF1",
                    MGF1ParameterSpec.SHA256,
                    PSource.PSpecified.DEFAULT
            );
}
