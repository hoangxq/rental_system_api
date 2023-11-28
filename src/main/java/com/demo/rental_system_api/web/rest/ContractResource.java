package com.demo.rental_system_api.web.rest;

import com.demo.rental_system_api.service.ContractService;
import com.demo.rental_system_api.web.dto.request.CreateContractRequest;
import com.demo.rental_system_api.web.dto.response.utils.ResponseUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/contracts")
@CrossOrigin("*")
public class ContractResource {
    private final ContractService contractService;

    @GetMapping("/client/{clientId}")
    public ResponseEntity<?> getContractOfClient(@PathVariable Integer clientId) {
        return ResponseUtils.ok(contractService.getContractOfClient(clientId));
    }

    @GetMapping("/{contractId}")
    public ResponseEntity<?> getContractById(@PathVariable Integer contractId) {
        return ResponseUtils.ok(contractService.getContractById(contractId));
    }

    @PostMapping
    public ResponseEntity<?> createContract(@Valid @RequestBody CreateContractRequest createContractRequest) {
        return ResponseUtils.ok(contractService.createContract(createContractRequest));
    }
}
