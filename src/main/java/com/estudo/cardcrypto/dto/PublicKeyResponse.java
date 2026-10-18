package com.estudo.cardcrypto.dto;

public record PublicKeyResponse(
        String algorithm,
        String publicKey
) {
}
