package com.demo.rental_system_api.model;

import lombok.Data;

import javax.persistence.*;

@Data
@Entity
@Table(name = "buildings")
public class Building {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    private String name;
    private String address;
    private String description;
}
