package com.demo.rental_system_api.web.dto;

import com.demo.rental_system_api.web.security.AuthoritiesConstants;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@NoArgsConstructor
@AllArgsConstructor
@Data
@Builder
public class AccountDto {
    private Integer id;
    private String username;
    private String email;
    private AuthoritiesConstants role;
}
