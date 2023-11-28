package com.demo.rental_system_api.service.impl;

import com.demo.rental_system_api.model.Building;
import com.demo.rental_system_api.model.Room;
import com.demo.rental_system_api.model.constants.RoomStatus;
import com.demo.rental_system_api.repository.BuildingRepository;
import com.demo.rental_system_api.repository.RoomRepository;
import com.demo.rental_system_api.service.RoomService;
import com.demo.rental_system_api.service.utils.MappingHelper;
import com.demo.rental_system_api.web.dto.BuildingDto;
import com.demo.rental_system_api.web.dto.RoomDto;
import com.demo.rental_system_api.web.dto.request.CreateRoomRequest;
import com.demo.rental_system_api.web.dto.request.UpdateRoomRequest;
import com.demo.rental_system_api.web.exception.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class RoomServiceImpl implements RoomService {
    private final RoomRepository roomRepository;
    private final BuildingRepository buildingRepository;
    private final MappingHelper mappingHelper;

    @Override
    public List<RoomDto> getAllRooms() {
        return roomRepository
                .findAll()
                .stream()
                .map(this::mapToRoomDto)
                .collect(Collectors.toList());
    }

    @Override
    public RoomDto getRoomById(Integer roomId) {
        return roomRepository
                .findById(roomId)
                .map(this::mapToRoomDto)
                .orElseThrow(() -> new EntityNotFoundException(
                        Room.class.getName(),
                        roomId.toString()
                ));
    }

    @Override
    @Transactional
    public RoomDto createRoom(CreateRoomRequest createRoomRequest) {
        var building = buildingRepository
                .findByNameAndAddress(
                        createRoomRequest.getBuildingRequest().getName(),
                        createRoomRequest.getBuildingRequest().getAddress())
                .orElseGet(() -> {
                    var newBuilding = mappingHelper.map(
                            createRoomRequest.getBuildingRequest(),
                            Building.class
                    );
                    return buildingRepository.save(newBuilding);
                });

        var room = mappingHelper.map(createRoomRequest, Room.class);
        room.setBuilding(building);
        room.setRoomStatus(RoomStatus.AVAILABLE);
        roomRepository.save(room);

        return mapToRoomDto(room);
    }

    @Override
    @Transactional
    public RoomDto updateRoom(Integer roomId, UpdateRoomRequest updateRoomRequest) {
        var room = roomRepository
                .findById(roomId)
                .orElseThrow(() -> new EntityNotFoundException(
                        Room.class.getName(),
                        roomId.toString()
                ));

        var building = buildingRepository
                .findByNameAndAddress(
                        updateRoomRequest.getBuildingRequest().getName(),
                        updateRoomRequest.getBuildingRequest().getAddress())
                .orElseGet(() -> {
                    var newBuilding = mappingHelper.map(
                            updateRoomRequest.getBuildingRequest(),
                            Building.class
                    );
                    return buildingRepository.save(newBuilding);
                });

        mappingHelper.mapIfSourceNotNullAndStringNotBlank(updateRoomRequest, room);
        room.setBuilding(building);
        roomRepository.save(room);

        return mapToRoomDto(room);
    }

    @Override
    @Transactional
    public Integer deleteRoom(Integer roomId) {
        var room = roomRepository
                .findById(roomId)
                .orElseThrow(() -> new EntityNotFoundException(
                        Room.class.getName(),
                        roomId.toString()
                ));
        roomRepository.delete(room);
        return roomId;
    }

    private RoomDto mapToRoomDto(Room room) {
        var roomDto = mappingHelper.map(room, RoomDto.class);
        roomDto.setBuildingDto(mappingHelper.map(room.getBuilding(), BuildingDto.class));
        return roomDto;
    }
}
