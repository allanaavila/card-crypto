package com.estudo.cardcrypto.service;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RsaPublicKeyUtil {

    public static PublicKey fromBase64(String publicKeyBase64) throws GeneralSecurityException {

        byte[] keyBytes = Base64.getDecoder()
                .decode(publicKeyBase64);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePublic(keySpec);
    }
}
