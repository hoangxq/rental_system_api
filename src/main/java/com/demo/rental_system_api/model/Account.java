package com.demo.rental_system_api.model;

import com.demo.rental_system_api.web.security.AuthoritiesConstants;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import javax.validation.constraints.Email;
import javax.validation.constraints.NotNull;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "accounts")
public class Account {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    @NotNull
    @Column(name = "username", unique = true, nullable = false)
    private String username;
    @JsonIgnore
    @NotNull
    @Column(name = "password_hash", nullable = false)
    private String password;
    @Email
    @Column(name = "email", unique = true)
    private String email;
    @Column(name = "role")
    private AuthoritiesConstants role;

    private String activationCode;
    private boolean active;
}
