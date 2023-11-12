package com.demo.rental_system_api.service;

import com.demo.rental_system_api.web.dto.ClientDto;
import com.demo.rental_system_api.web.dto.request.ClientRequest;

import java.util.List;

public interface ClientService {
    List<ClientDto> getAllClients();

    ClientDto getClientById(Integer clientId);

    ClientDto createClient(ClientRequest clientRequest);

    ClientDto updateClient(Integer clientId, ClientRequest clientRequest);

    Integer deleteClient(Integer clientId);
}
