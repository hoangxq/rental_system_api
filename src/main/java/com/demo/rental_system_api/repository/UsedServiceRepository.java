package com.demo.rental_system_api.repository;

import com.demo.rental_system_api.model.UsedService;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface UsedServiceRepository extends JpaRepository<UsedService, Integer> {
    List<UsedService> findByMonthBill_Id(Integer monthBillId);
}
