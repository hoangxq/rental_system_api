package com.demo.rental_system_api.web.dto.request;

import com.demo.rental_system_api.model.constants.RoomStatus;
import lombok.Data;

@Data
public class UpdateRoomRequest {
    private String name;
    private String type;
    private Float roomArea;
    private RoomStatus roomStatus;
    private Float price;
    private String description;
}
