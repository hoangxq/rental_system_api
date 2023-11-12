package com.demo.rental_system_api.web.dto;

import com.demo.rental_system_api.model.constants.ClientStatus;
import lombok.Data;

@Data
public class ClientDto {
    private Integer id;
    private String fullName;
    private String phoneNumber;
    private String email;
    private String address;
    private String idCard;
    private String note;
    private ClientStatus clientStatus;
}
