package com.demo.rental_system_api.web.dto.request;

import lombok.Data;

import javax.validation.constraints.NotBlank;

@Data
public class LoginWithEmailRequest {
    @NotBlank
    private String email;
    @NotBlank
    private String activeCode;
}
