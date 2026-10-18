package com.estudo.cardcrypto.entity;

import jakarta.persistence.*;

@Entity
@Table(name = "rsa_keys")
public class RsaKeyEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String kid;

    @Column(nullable = false)
    private String algorithm;

    protected RsaKeyEntity() {}

    public RsaKeyEntity(String kid, String algorithm) {
        this.kid = kid;
        this.algorithm = algorithm;
    }

    public Long getId() {
        return id;
    }

    public String getKid() {
        return kid;
    }

    public String getAlgorithm() {
        return algorithm;
    }
}
