package com.estudo.cardcrypto.dto;

import jakarta.validation.constraints.NotBlank;

public record CryptoRequest(
        @NotBlank(message = "O campo value é obrigatório")
        String value
) {
}
