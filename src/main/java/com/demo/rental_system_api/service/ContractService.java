package com.demo.rental_system_api.service;

import com.demo.rental_system_api.web.dto.ContractDto;
import com.demo.rental_system_api.web.dto.request.CreateContractRequest;

import java.util.List;

public interface ContractService {
    List<ContractDto> getContractOfClient(Integer clientId);

    ContractDto getContractById(Integer contractId);

    ContractDto createContract(CreateContractRequest createContractRequest);
}
