package com.demo.rental_system_api.web.dto.request;

import lombok.Data;

@Data
public class CreateRoomRequest {
    private String name;
    private String type;
    private Float price;
    private Float roomArea;
    private String description;
    private BuildingRequest buildingRequest;

    @Data
    public static class BuildingRequest {
        private String name;
        private String address;
        private String description = "None";
    }
}
