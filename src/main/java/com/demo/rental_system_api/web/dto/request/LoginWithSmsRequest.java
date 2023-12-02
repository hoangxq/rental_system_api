package com.demo.rental_system_api.web.dto.request;

import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
public class LoginWithSmsRequest {
    @NotBlank
    private String username;
    @NotBlank
    private String activeCode;
}
