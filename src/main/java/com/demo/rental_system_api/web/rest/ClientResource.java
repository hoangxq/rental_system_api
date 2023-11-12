package com.demo.rental_system_api.web.rest;

import com.demo.rental_system_api.service.ClientService;
import com.demo.rental_system_api.service.RoomService;
import com.demo.rental_system_api.web.dto.request.ClientRequest;
import com.demo.rental_system_api.web.dto.request.CreateRoomRequest;
import com.demo.rental_system_api.web.dto.request.UpdateRoomRequest;
import com.demo.rental_system_api.web.dto.response.utils.ResponseUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/clients")
@CrossOrigin("*")
public class ClientResource {
    private final ClientService clientService;

    @GetMapping
    public ResponseEntity<?> getAllClients() {
        return ResponseUtils.ok(clientService.getAllClients());
    }

    @GetMapping("/{clientId}")
    public ResponseEntity<?> getClientById(@PathVariable Integer clientId) {
        return ResponseUtils.ok(clientService.getClientById(clientId));
    }

    @PostMapping
    public ResponseEntity<?> createClient(@Valid @RequestBody ClientRequest clientRequest) {
        return ResponseUtils.ok(clientService.createClient(clientRequest));
    }

    @PutMapping("/{clientId}")
    public ResponseEntity<?> updateClient(@Valid @RequestBody ClientRequest clientRequest, @PathVariable Integer clientId) {
        return ResponseUtils.ok(clientService.updateClient(clientId, clientRequest));
    }

    @DeleteMapping("/{clientId}")
    public ResponseEntity<?> deleteClient(@PathVariable Integer clientId) {
        return ResponseUtils.ok(clientService.deleteClient(clientId));
    }
}
