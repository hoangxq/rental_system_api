package com.demo.rental_system_api.model;

import lombok.Data;

import javax.persistence.*;
import java.util.Date;

@Data
@Entity
@Table(name = "month_bills")
public class MonthBill {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;
    private Date dueDate;
    private Date paymentDate;
    private Float totalPrice;
    private String note;

    @ManyToOne
    @JoinColumn(name = "contract_id")
    private Contract contract;
}
