package com.estudo.cardcrypto.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "crypto.rsa.keystore")
public record RsaKeyStoreProperties(
        String path,
        String password,
        String alias
) {
}
