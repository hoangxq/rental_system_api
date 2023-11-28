package com.demo.rental_system_api.service.impl;

import com.demo.rental_system_api.model.Service;
import com.demo.rental_system_api.repository.ServiceRepository;
import com.demo.rental_system_api.service.ServicesService;
import com.demo.rental_system_api.service.utils.MappingHelper;
import com.demo.rental_system_api.web.dto.ServiceDto;
import com.demo.rental_system_api.web.dto.request.ServiceRequest;
import com.demo.rental_system_api.web.exception.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.util.List;
import java.util.stream.Collectors;

@org.springframework.stereotype.Service
@Slf4j
@RequiredArgsConstructor
public class ServicesServiceImpl implements ServicesService {
    private final ServiceRepository serviceRepository;
    private final MappingHelper mappingHelper;

    @Override
    public List<ServiceDto> getAllServices() {
        return serviceRepository
                .findAll()
                .stream()
                .map(this::mapDataToServiceDto)
                .collect(Collectors.toList());
    }

    @Override
    public ServiceDto getServiceById(Integer serviceId) {
        return serviceRepository
                .findById(serviceId)
                .map(this::mapDataToServiceDto)
                .orElseThrow(() -> new EntityNotFoundException(
                        Service.class.getName(),
                        serviceId.toString()
                ));
    }

    @Override
    public ServiceDto createService(ServiceRequest serviceRequest) {
        var service = mappingHelper.map(serviceRequest, Service.class);
        serviceRepository.save(service);
        return mapDataToServiceDto(service);
    }

    @Override
    public ServiceDto updateService(Integer serviceId, ServiceRequest serviceRequest) {
        var service = serviceRepository
                .findById(serviceId)
                .orElseThrow(() -> new EntityNotFoundException(
                        Service.class.getName(),
                        serviceId.toString()
                ));

        mappingHelper.mapIfSourceNotNullAndStringNotBlank(serviceRequest, service);
        serviceRepository.save(service);
        return mapDataToServiceDto(service);
    }

    @Override
    public Integer deleteService(Integer serviceId) {
        var service = serviceRepository
                .findById(serviceId)
                .orElseThrow(() -> new EntityNotFoundException(
                        Service.class.getName(),
                        serviceId.toString()
                ));
        serviceRepository.delete(service);
        return serviceId;
    }

    private ServiceDto mapDataToServiceDto(Service service) {
        return mappingHelper.map(service, ServiceDto.class);
    }
}
