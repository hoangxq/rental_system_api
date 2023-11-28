package com.demo.rental_system_api.repository;

import com.demo.rental_system_api.model.MonthBill;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface MonthBillRepository extends JpaRepository<MonthBill, Integer> {
    List<MonthBill> findByContract_Id(Integer contractId);
}
