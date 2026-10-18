package com.estudo.cardcrypto.dto;

public record ErrorResponse(
        int status,
        String message
) {
}
