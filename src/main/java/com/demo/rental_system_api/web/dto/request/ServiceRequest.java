package com.demo.rental_system_api.web.dto.request;

import lombok.Data;

@Data
public class ServiceRequest {
    private String name;
    private Float price;
    private String description;
}
