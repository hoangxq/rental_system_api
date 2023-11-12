package com.demo.rental_system_api.repository;

import com.demo.rental_system_api.model.Contract;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ContractRepository extends JpaRepository<Contract, Integer> {
}
