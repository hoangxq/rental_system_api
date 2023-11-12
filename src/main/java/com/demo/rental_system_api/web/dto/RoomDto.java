package com.demo.rental_system_api.web.dto;

import com.demo.rental_system_api.model.constants.RoomStatus;
import lombok.Data;

@Data
public class RoomDto {
    private Integer id;
    private String name;
    private String type;
    private Float price;
    private RoomStatus roomStatus;
    private String description;
    private BuildingDto buildingDto;
}
