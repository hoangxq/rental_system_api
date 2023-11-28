package com.demo.rental_system_api.service;

import com.demo.rental_system_api.web.dto.MonthBillDto;
import com.demo.rental_system_api.web.dto.request.CreateMonthBillRequest;

import java.util.List;

public interface MonthBillService {
    List<MonthBillDto> getBillOfContract(Integer contractId);

    MonthBillDto getBillById(Integer billId);

    MonthBillDto createBill(CreateMonthBillRequest createMonthBillRequest);
}
