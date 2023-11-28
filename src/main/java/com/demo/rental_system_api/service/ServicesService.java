package com.demo.rental_system_api.service;

import com.demo.rental_system_api.web.dto.ServiceDto;
import com.demo.rental_system_api.web.dto.request.ServiceRequest;

import java.util.List;

public interface ServicesService {
    List<ServiceDto> getAllServices();

    ServiceDto getServiceById(Integer serviceId);

    ServiceDto createService(ServiceRequest serviceRequest);

    ServiceDto updateService(Integer serviceId, ServiceRequest serviceRequest);

    Integer deleteService(Integer serviceId);
}
