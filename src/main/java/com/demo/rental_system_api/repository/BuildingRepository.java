package com.demo.rental_system_api.repository;

import com.demo.rental_system_api.model.Building;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface BuildingRepository extends JpaRepository<Building, Integer> {
    Optional<Building> findByNameAndAddress(String name, String address);
}
