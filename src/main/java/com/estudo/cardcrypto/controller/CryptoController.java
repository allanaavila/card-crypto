package com.estudo.cardcrypto.controller;

import com.estudo.cardcrypto.dto.CryptoRequest;
import com.estudo.cardcrypto.dto.CryptoResponse;
import com.estudo.cardcrypto.service.RsaCryptoService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.GeneralSecurityException;

@RestController
@RequestMapping("/api/crypto/rsa")
public class CryptoController {

    private final RsaCryptoService rsaCryptoService;

    public CryptoController(RsaCryptoService rsaCryptoService) {
        this.rsaCryptoService = rsaCryptoService;
    }

    @PostMapping("/encrypt")
    public ResponseEntity<CryptoResponse> encrypt (@Valid @RequestBody
                                                   CryptoRequest request) throws GeneralSecurityException {
        String encrypted = rsaCryptoService.encrypt(request.value());

        CryptoResponse response = new CryptoResponse(encrypted);

        return ResponseEntity.ok(response);
    }

    @PostMapping("/decrypt")
    public ResponseEntity<CryptoResponse> decrypt (@Valid @RequestBody
                                                   CryptoRequest request ) throws  GeneralSecurityException {
        String decrypted = rsaCryptoService.decrypt(request.value());

        CryptoResponse response = new CryptoResponse(decrypted);

        return ResponseEntity.ok(response);
    }
}
