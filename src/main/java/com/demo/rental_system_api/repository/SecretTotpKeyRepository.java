package com.demo.rental_system_api.repository;

import com.demo.rental_system_api.model.SecretTotpKey;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface SecretTotpKeyRepository extends JpaRepository<SecretTotpKey, Integer> {
    Optional<SecretTotpKey> findByAccount_Username(String email);
}
