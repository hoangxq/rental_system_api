package com.demo.rental_system_api.repository;

import com.demo.rental_system_api.model.MonthBill;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MonthBillRepository extends JpaRepository<MonthBill, Integer> {
}
