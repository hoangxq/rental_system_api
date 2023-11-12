package com.demo.rental_system_api.web.dto.response;

import lombok.Data;

@Data
public class AccountResponse {
    private Long id;
    private String username;
    private String email;
}
