package com.demo.rental_system_api.model;

import lombok.Data;

import javax.persistence.*;

@Data
@Entity
@Table(name = "secret_totp_keys")
public class SecretTotpKey {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @OneToOne
    @JoinColumn(name = "account_id")
    private Account account;
    private String secret;
    private Boolean active;
}
