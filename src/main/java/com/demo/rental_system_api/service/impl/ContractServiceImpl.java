package com.demo.rental_system_api.service.impl;

import com.demo.rental_system_api.model.Client;
import com.demo.rental_system_api.model.Contract;
import com.demo.rental_system_api.model.Room;
import com.demo.rental_system_api.model.constants.ClientStatus;
import com.demo.rental_system_api.repository.ClientRepository;
import com.demo.rental_system_api.repository.ContractRepository;
import com.demo.rental_system_api.repository.RoomRepository;
import com.demo.rental_system_api.service.ContractService;
import com.demo.rental_system_api.service.utils.MappingHelper;
import com.demo.rental_system_api.web.dto.BuildingDto;
import com.demo.rental_system_api.web.dto.ClientDto;
import com.demo.rental_system_api.web.dto.ContractDto;
import com.demo.rental_system_api.web.dto.RoomDto;
import com.demo.rental_system_api.web.dto.request.CreateContractRequest;
import com.demo.rental_system_api.web.exception.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class ContractServiceImpl implements ContractService {
    private final ContractRepository contractRepository;
    private final ClientRepository clientRepository;
    private final RoomRepository roomRepository;
    private final MappingHelper mappingHelper;

    @Override
    public List<ContractDto> getContractOfClient(Integer clientId) {
        return contractRepository
                .findByClient_Id(clientId)
                .stream()
                .map(this::mapToContractDto)
                .collect(Collectors.toList());
    }

    @Override
    public ContractDto getContractById(Integer contractId) {
        return contractRepository
                .findById(contractId)
                .map(this::mapToContractDto)
                .orElseThrow(() -> new EntityNotFoundException(
                        Contract.class.getName(),
                        contractId.toString()
                ));
    }

    @Override
    @Transactional
    public ContractDto createContract(CreateContractRequest createContractRequest) {
        var room = roomRepository
                .findById(createContractRequest.getRoomId())
                .orElseThrow(() -> new EntityNotFoundException(
                        Room.class.getName(),
                        createContractRequest.getRoomId().toString()
                ));

        var client = clientRepository
                .findById(createContractRequest.getClientId())
                .orElseThrow(() -> new EntityNotFoundException(
                        Client.class.getName(),
                        createContractRequest.getClientId().toString()
                ));

        var contract = mappingHelper.map(createContractRequest, Contract.class);
        contract.setRoom(room);
        contract.setClient(client);
        contract.setCreatedAt(new Date());
        contractRepository.save(contract);

        client.setClientStatus(ClientStatus.RENTED);
        clientRepository.save(client);

        return mapToContractDto(contract);
    }

    private ContractDto mapToContractDto(Contract contract) {
        var contractDto = mappingHelper.map(contract, ContractDto.class);
        var roomDto = mappingHelper.map(contract.getRoom(), RoomDto.class);
        roomDto.setBuildingDto(mappingHelper.map(contract.getRoom().getBuilding(), BuildingDto.class));
        contractDto.setRoomDto(roomDto);
        contractDto.setClientDto(mappingHelper.map(contract.getClient(), ClientDto.class));
        return contractDto;
    }
}
