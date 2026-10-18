
package com.estudo.cardcrypto.service;

import com.estudo.cardcrypto.config.RsaKeyStoreProperties;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.GeneralSecurityException;
import java.io.IOException;

import java.nio.file.Files;
import java.nio.file.Path;

@Service
public class RsaKeyStoreService {

    private final RsaKeyStoreProperties properties;

    public RsaKeyStoreService(
            RsaKeyStoreProperties properties
    ) {
        this.properties = properties;
    }

    public boolean keyStoreExists() {
        Path path = Path.of(properties.path());

        return Files.isRegularFile(path);
    }


    public void createKeyStore()
            throws GeneralSecurityException, IOException {

        Path path = Path.of(properties.path());

        if (Files.exists(path)) {
            throw new IllegalStateException(
                    "Já existe um arquivo no caminho do KeyStore"
            );
        }

        Path parent = path.toAbsolutePath().getParent();

        if (parent != null) {
            Files.createDirectories(parent);
        }

        KeyStore keyStore = KeyStore.getInstance("PKCS12");

        char[] password = properties.password().toCharArray();

        keyStore.load(null, password);

        try (OutputStream output = Files.newOutputStream(path)) {
            keyStore.store(output, password);
        }
    }


    public KeyStore loadKeyStore()
            throws GeneralSecurityException, IOException {

        Path path = Path.of(properties.path());

        if (!Files.isRegularFile(path)) {
            throw new IOException(
                    "Arquivo KeyStore não encontrado: " + path
            );
        }

        KeyStore keyStore = KeyStore.getInstance("PKCS12");

        char[] password = properties.password().toCharArray();

        try (InputStream input = Files.newInputStream(path)) {
            keyStore.load(input, password);
        }

        return keyStore;
    }

}
