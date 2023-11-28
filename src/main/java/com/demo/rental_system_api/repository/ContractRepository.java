package com.demo.rental_system_api.repository;

import com.demo.rental_system_api.model.Contract;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ContractRepository extends JpaRepository<Contract, Integer> {
    List<Contract> findByClient_Id(Integer clientId);
}
