package com.demo.rental_system_api.model;

import lombok.Data;

import javax.persistence.*;

@Data
@Entity
@Table(name = "used_services")
public class UsedService {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    private Integer quantity;
    private Float totalPrice;

    @ManyToOne
    @JoinColumn(name = "service_id")
    private Service service;

    @ManyToOne
    @JoinColumn(name = "month_bill_id")
    private MonthBill monthBill;
}
