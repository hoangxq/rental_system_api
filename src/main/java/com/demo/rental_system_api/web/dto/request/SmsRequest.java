package com.demo.rental_system_api.web.dto.request;

import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
public class SmsRequest {
    @NotBlank
    private final String phoneNumber;
    @NotBlank
    private final String message;
}
