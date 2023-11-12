package com.demo.rental_system_api.web.dto.request;

import com.demo.rental_system_api.model.constants.ClientStatus;
import lombok.Data;

@Data
public class ClientRequest {
    private String fullName;
    private String phoneNumber;
    private String email;
    private String address;
    private String idCard;
    private String note;
    private ClientStatus clientStatus;
}
