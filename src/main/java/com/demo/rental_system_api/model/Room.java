package com.demo.rental_system_api.model;

import com.demo.rental_system_api.model.constants.RoomStatus;
import lombok.Data;

import javax.persistence.*;

@Data
@Entity
@Table(name = "rooms")
public class Room {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    private String name;
    private String type;
    private Float price;
    private String description;
    private RoomStatus roomStatus;

    @ManyToOne
    @JoinColumn(name = "building_id")
    private Building building;
}
