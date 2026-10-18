package com.estudo.cardcrypto.dto;

public record PublicKeyResponse(
        String kid,
        String algorithm,
        String publicKey
) {
}
