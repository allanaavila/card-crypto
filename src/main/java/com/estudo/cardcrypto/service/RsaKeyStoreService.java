
package com.estudo.cardcrypto.service;

import com.estudo.cardcrypto.config.RsaKeyStoreProperties;
import org.springframework.stereotype.Service;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import java.io.IOException;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

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

    public boolean containsKeyAlias()
            throws GeneralSecurityException, IOException {

        KeyStore keyStore = loadKeyStore();

        return keyStore.containsAlias(properties.alias());
    }


    public void saveKeyPair(
            KeyPair keyPair,
            X509Certificate certificate
    ) throws GeneralSecurityException, IOException {

        KeyStore keyStore = loadKeyStore();

        char[] password = properties.password().toCharArray();

        Certificate[] certificateChain = {
                certificate
        };

        keyStore.setKeyEntry(
                properties.alias(),
                keyPair.getPrivate(),
                password,
                certificateChain
        );

        Path path = Path.of(properties.path());

        try (OutputStream output = Files.newOutputStream(path)) {
            keyStore.store(output, password);
        }
    }


    public KeyPair loadKeyPair()
            throws GeneralSecurityException, IOException {

        KeyStore keyStore = loadKeyStore();

        String alias = properties.alias();
        char[] password = properties.password().toCharArray();

        if (!keyStore.isKeyEntry(alias)) {
            throw new KeyStoreException(
                    "Chave RSA não encontrada no KeyStore: " + alias
            );
        }

        PrivateKey privateKey = (PrivateKey) keyStore.getKey(
                alias,
                password
        );

        Certificate certificate = keyStore.getCertificate(alias);

        if (certificate == null) {
            throw new KeyStoreException(
                    "Certificado não encontrado para o alias: " + alias
            );
        }

        PublicKey publicKey = certificate.getPublicKey();

        return new KeyPair(publicKey, privateKey);
    }
}
