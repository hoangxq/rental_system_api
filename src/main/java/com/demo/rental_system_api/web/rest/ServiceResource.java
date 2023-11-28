package com.demo.rental_system_api.web.rest;

import com.demo.rental_system_api.service.ServicesService;
import com.demo.rental_system_api.web.dto.request.ServiceRequest;
import com.demo.rental_system_api.web.dto.response.utils.ResponseUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RequiredArgsConstructor
@RestController
@RequestMapping("/api/services")
@CrossOrigin("*")
public class ServiceResource {
    private final ServicesService servicesService;

    @GetMapping
    public ResponseEntity<?> getAllServices() {
        return ResponseUtils.ok(servicesService.getAllServices());
    }

    @GetMapping("/{serviceId}")
    public ResponseEntity<?> getServiceById(@PathVariable Integer serviceId) {
        return ResponseUtils.ok(servicesService.getServiceById(serviceId));
    }

    @PostMapping
    public ResponseEntity<?> createService(@Valid @RequestBody ServiceRequest serviceRequest) {
        return ResponseUtils.ok(servicesService.createService(serviceRequest));
    }

    @PutMapping("/{serviceId}")
    public ResponseEntity<?> updateService(@Valid @RequestBody ServiceRequest serviceRequest, @PathVariable Integer serviceId) {
        return ResponseUtils.ok(servicesService.updateService(serviceId, serviceRequest));
    }

    @DeleteMapping("/{serviceId}")
    public ResponseEntity<?> deleteService(@PathVariable Integer serviceId) {
        return ResponseUtils.ok(servicesService.deleteService(serviceId));
    }
}
