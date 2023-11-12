package com.demo.rental_system_api.service;

import com.demo.rental_system_api.web.dto.RoomDto;
import com.demo.rental_system_api.web.dto.request.CreateRoomRequest;
import com.demo.rental_system_api.web.dto.request.UpdateRoomRequest;

import java.util.List;

public interface RoomService {
    List<RoomDto> getAllRooms();

    RoomDto getRoomById(Integer roomId);

    RoomDto createRoom(CreateRoomRequest createRoomRequest);

    RoomDto updateRoom(Integer roomId, UpdateRoomRequest updateRoomRequest);

    Integer deleteRoom(Integer roomId);
}
