package com.demo.rental_system_api.web.dto;

import lombok.Data;

@Data
public class ServiceDto {
    private Integer id;
    private String name;
    private Float price;
    private String description;
}
