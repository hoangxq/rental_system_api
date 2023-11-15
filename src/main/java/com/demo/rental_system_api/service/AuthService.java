package com.demo.rental_system_api.service;

import com.demo.rental_system_api.web.dto.request.LoginRequest;
import com.demo.rental_system_api.web.dto.request.LoginWithTotpRequest;
import com.demo.rental_system_api.web.dto.request.SignupRequest;
import com.demo.rental_system_api.web.dto.response.JwtResponse;

public interface AuthService {
    JwtResponse authenticateAccount(LoginRequest loginRequest);

    void registerAccount(SignupRequest signupRequest);

    void activateEmailCode(String code);

    String registerTotp();

    void registerTotpCode(String code);

    JwtResponse activeTotpCode(LoginWithTotpRequest request);
}
