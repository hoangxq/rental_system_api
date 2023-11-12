package com.demo.rental_system_api.service.impl;

import com.demo.rental_system_api.model.Client;
import com.demo.rental_system_api.repository.ClientRepository;
import com.demo.rental_system_api.service.ClientService;
import com.demo.rental_system_api.service.utils.MappingHelper;
import com.demo.rental_system_api.web.dto.ClientDto;
import com.demo.rental_system_api.web.dto.request.ClientRequest;
import com.demo.rental_system_api.web.exception.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class ClientServiceImpl implements ClientService {
    private final ClientRepository clientRepository;
    private final MappingHelper mappingHelper;

    @Override
    public List<ClientDto> getAllClients() {
        return clientRepository
                .findAll()
                .stream()
                .map(client -> mappingHelper.map(client, ClientDto.class))
                .collect(Collectors.toList());
    }

    @Override
    public ClientDto getClientById(Integer clientId) {
        return clientRepository
                .findById(clientId)
                .map(client -> mappingHelper.map(client, ClientDto.class))
                .orElseThrow(() -> new EntityNotFoundException(
                        Client.class.getName(),
                        clientId.toString()
                ));
    }

    @Override
    @Transactional
    public ClientDto createClient(ClientRequest clientRequest) {
        var client = mappingHelper.map(clientRequest, Client.class);
        clientRepository.save(client);
        return mappingHelper.map(client, ClientDto.class);
    }

    @Override
    @Transactional
    public ClientDto updateClient(Integer clientId, ClientRequest clientRequest) {
        var client = clientRepository
                .findById(clientId)
                .orElseThrow(() -> new EntityNotFoundException(
                        Client.class.getName(),
                        clientId.toString()
                ));
        mappingHelper.mapIfSourceNotNullAndStringNotBlank(clientRequest, client);
        clientRepository.save(client);
        return mappingHelper.map(client, ClientDto.class);
    }

    @Override
    @Transactional
    public Integer deleteClient(Integer clientId) {
        var client = clientRepository
                .findById(clientId)
                .orElseThrow(() -> new EntityNotFoundException(
                        Client.class.getName(),
                        clientId.toString()
                ));
        clientRepository.delete(client);
        return clientId;
    }
}
