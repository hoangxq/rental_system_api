package com.demo.rental_system_api.service.impl;

import com.demo.rental_system_api.model.Contract;
import com.demo.rental_system_api.model.MonthBill;
import com.demo.rental_system_api.model.UsedService;
import com.demo.rental_system_api.repository.ContractRepository;
import com.demo.rental_system_api.repository.MonthBillRepository;
import com.demo.rental_system_api.repository.ServiceRepository;
import com.demo.rental_system_api.repository.UsedServiceRepository;
import com.demo.rental_system_api.service.MonthBillService;
import com.demo.rental_system_api.service.utils.MappingHelper;
import com.demo.rental_system_api.web.dto.*;
import com.demo.rental_system_api.web.dto.request.CreateMonthBillRequest;
import com.demo.rental_system_api.web.exception.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.DoubleStream;

@Service
@Slf4j
@RequiredArgsConstructor
public class MonthBillServiceImpl implements MonthBillService {
    private final MonthBillRepository monthBillRepository;
    private final ContractRepository contractRepository;
    private final UsedServiceRepository usedServiceRepository;
    private final ServiceRepository serviceRepository;
    private final MappingHelper mappingHelper;

    @Override
    public List<MonthBillDto> getBillOfContract(Integer contractId) {
        return monthBillRepository
                .findByContract_Id(contractId)
                .stream()
                .map(this::mapToMonthBillDto)
                .collect(Collectors.toList());
    }

    @Override
    public MonthBillDto getBillById(Integer billId) {
        return monthBillRepository
                .findById(billId)
                .map(this::mapToMonthBillDto)
                .orElseThrow(() -> new EntityNotFoundException(
                        MonthBill.class.getName(),
                        billId.toString()
                ));
    }

    @Override
    @Transactional
    public MonthBillDto createBill(CreateMonthBillRequest createMonthBillRequest) {
        var contract = contractRepository
                .findById(createMonthBillRequest.getContractId())
                .orElseThrow(() -> new EntityNotFoundException(
                        Contract.class.getName(),
                        createMonthBillRequest.getContractId().toString()
                ));

        var monthBill = mappingHelper.map(createMonthBillRequest, MonthBill.class);
        monthBill.setContract(contract);

        var usedServices = serviceRepository
                .findAllById(
                        createMonthBillRequest.getUsedServiceRequests()
                                .stream()
                                .map(CreateMonthBillRequest.UsedServiceRequest::getServiceId)
                                .collect(Collectors.toList()))
                .stream()
                .map(service -> {
                    var usedServiceReq = createMonthBillRequest
                            .getUsedServiceRequests()
                            .stream().filter(e -> e.getServiceId().equals(service.getId()))
                            .findFirst();
                    if (usedServiceReq.isPresent()) {
                        var usedService = mappingHelper.map(usedServiceReq.get(), UsedService.class);
                        usedService.setService(service);
                        usedService.setMonthBill(monthBill);
                        usedService.setTotalPrice(service.getPrice() * usedServiceReq.get().getQuantity());
                        return usedService;
                    }
                    return null;
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toList());

        usedServiceRepository.saveAll(usedServices);

        var totalPriceBill = contract.getRoom().getPrice()
                - contract.getRoomDeposit()
                + usedServices.stream().flatMapToDouble(e -> DoubleStream.of(e.getTotalPrice())).sum();

        monthBill.setTotalPrice((float) totalPriceBill);
        monthBillRepository.save(monthBill);

        return mapToMonthBillDto(monthBill);
    }

    private MonthBillDto mapToMonthBillDto(MonthBill monthBill) {
        var monthBillDto = mappingHelper.map(monthBill, MonthBillDto.class);
        monthBillDto.setContractDto(mapToContractDto(monthBill.getContract()));

        var usedServiceDtoList = usedServiceRepository
                .findByMonthBill_Id(monthBill.getId())
                .stream()
                .map(this::mapDataToUsedServiceDto)
                .collect(Collectors.toList());

        monthBillDto.setUsedServiceDtoList(usedServiceDtoList);

        return monthBillDto;
    }

    private ContractDto mapToContractDto(Contract contract) {
        var contractDto = mappingHelper.map(contract, ContractDto.class);
        var roomDto = mappingHelper.map(contract.getRoom(), RoomDto.class);
        roomDto.setBuildingDto(mappingHelper.map(contract.getRoom().getBuilding(), BuildingDto.class));
        contractDto.setRoomDto(roomDto);
        contractDto.setClientDto(mappingHelper.map(contract.getClient(), ClientDto.class));
        return contractDto;
    }

    private MonthBillDto.UsedServiceDto mapDataToUsedServiceDto(UsedService usedService) {
        var usedServiceDto = mappingHelper.map(usedService, MonthBillDto.UsedServiceDto.class);
        usedServiceDto.setServiceDto(mappingHelper.map(usedService.getService(), ServiceDto.class));
        return usedServiceDto;
    }
}
