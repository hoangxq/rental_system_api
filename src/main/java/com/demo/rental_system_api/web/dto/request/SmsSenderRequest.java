package com.demo.rental_system_api.web.dto.request;

import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
public class SmsSenderRequest {
    @NotBlank
    private String phoneNumber;
    @NotBlank
    private String username;
}
