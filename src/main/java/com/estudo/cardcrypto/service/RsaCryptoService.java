package com.estudo.cardcrypto.service;

import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;

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

        // Configurar o algoritmo de criptografia RSA
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");

        // Inicializar com chave publica
        cipher.init(
                Cipher.ENCRYPT_MODE, rsaKeyService.getPublicKey()
        );

        // Converter texto em bytes
        byte[] textBytes = text.getBytes(StandardCharsets.UTF_8);

        // Criptografar os bytes
        byte[] encryptedBytes = cipher.doFinal(textBytes);

        // Converter o resultado para Base64
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }
}
