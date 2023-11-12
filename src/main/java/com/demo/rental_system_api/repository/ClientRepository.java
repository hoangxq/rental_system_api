package com.demo.rental_system_api.repository;

import com.demo.rental_system_api.model.Client;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ClientRepository extends JpaRepository<Client, Integer> {
}
