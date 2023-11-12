package com.demo.rental_system_api.web.dto.request;

import lombok.Data;

@Data
public class UpdateRoomRequest {
    private String name;
    private String type;
    private Float price;
    private String description;
}
