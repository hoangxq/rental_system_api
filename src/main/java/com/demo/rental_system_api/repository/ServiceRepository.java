package com.demo.rental_system_api.repository;

import com.demo.rental_system_api.model.Service;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ServiceRepository extends JpaRepository<Service, Integer> {
}
