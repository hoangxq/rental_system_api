package com.demo.rental_system_api.web.rest;

import com.demo.rental_system_api.service.MonthBillService;
import com.demo.rental_system_api.web.dto.request.CreateMonthBillRequest;
import com.demo.rental_system_api.web.dto.response.utils.ResponseUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/month-bills")
@CrossOrigin("*")
public class MonthBillResource {
    private final MonthBillService monthBillService;

    @GetMapping("/contract/{contractId}")
    public ResponseEntity<?> getBillOfContract(@PathVariable Integer contractId) {
        return ResponseUtils.ok(monthBillService.getBillOfContract(contractId));
    }

    @GetMapping("/{billId}")
    public ResponseEntity<?> getBillById(@PathVariable Integer billId) {
        return ResponseUtils.ok(monthBillService.getBillById(billId));
    }

    @PostMapping
    public ResponseEntity<?> createBill(@Valid @RequestBody CreateMonthBillRequest createMonthBillRequest) {
        return ResponseUtils.ok(monthBillService.createBill(createMonthBillRequest));
    }
}
