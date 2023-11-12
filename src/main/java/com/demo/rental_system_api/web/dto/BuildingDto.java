package com.demo.rental_system_api.web.dto;

import lombok.Data;

@Data
public class BuildingDto {
    private Integer id;
    private String name;
    private String address;
    private String description;
}
