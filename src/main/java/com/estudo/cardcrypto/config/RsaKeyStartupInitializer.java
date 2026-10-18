package com.estudo.cardcrypto.config;

import com.estudo.cardcrypto.service.RsaKeyMetadataService;
import com.estudo.cardcrypto.service.RsaKeyService;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

@Component
@Profile("dev")
public class RsaKeyStartupInitializer implements ApplicationRunner {

    private final RsaKeyService rsaKeyService;
    private final RsaKeyMetadataService metadataService;

    public RsaKeyStartupInitializer(
            RsaKeyService rsaKeyService,
            RsaKeyMetadataService metadataService
    ) {
        this.rsaKeyService = rsaKeyService;
        this.metadataService = metadataService;
    }

    @Override
    public void run(ApplicationArguments args) {

        metadataService.salvar(
                rsaKeyService.getKeyId(),
                "RSA"
        );
    }
}
