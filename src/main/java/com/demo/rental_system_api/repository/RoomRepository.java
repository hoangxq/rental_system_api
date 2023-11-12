package com.demo.rental_system_api.repository;

import com.demo.rental_system_api.model.Room;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RoomRepository extends JpaRepository<Room, Integer> {
}
