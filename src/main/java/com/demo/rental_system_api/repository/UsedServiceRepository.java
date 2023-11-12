package com.demo.rental_system_api.repository;

import com.demo.rental_system_api.model.UsedService;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UsedServiceRepository extends JpaRepository<UsedService, Integer> {
}
