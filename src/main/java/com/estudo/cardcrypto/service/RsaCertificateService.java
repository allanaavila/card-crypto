
package com.estudo.cardcrypto.service;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

@Service
public class RsaCertificateService {

    public X509Certificate generateSelfSignedCertificate(
            KeyPair keyPair
    ) throws Exception {

        Instant now = Instant.now();

        Date notBefore = Date.from(
                now.minus(1, ChronoUnit.MINUTES)
        );

        Date notAfter = Date.from(
                now.plus(365, ChronoUnit.DAYS)
        );

        X500Name subject = new X500Name(
                "CN=CardCrypto RSA Development"
        );

        BigInteger serialNumber = new BigInteger(
                160,
                new SecureRandom()
        ).abs();

        JcaX509v3CertificateBuilder builder =
                new JcaX509v3CertificateBuilder(
                        subject,
                        serialNumber,
                        notBefore,
                        notAfter,
                        subject,
                        keyPair.getPublic()
                );

        ContentSigner signer =
                new JcaContentSignerBuilder("SHA256withRSA")
                        .build(keyPair.getPrivate());

        X509CertificateHolder holder =
                builder.build(signer);

        return new JcaX509CertificateConverter()
                .getCertificate(holder);
    }
}
