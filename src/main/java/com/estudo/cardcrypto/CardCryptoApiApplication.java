package com.estudo.cardcrypto;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.estudo.cardcrypto.config.RsaKeyStoreProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(RsaKeyStoreProperties.class)
public class CardCryptoApiApplication {

	public static void main(String[] args) {
		SpringApplication.run(CardCryptoApiApplication.class, args);
	}

}
