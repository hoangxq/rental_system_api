package com.demo.rental_system_api.web.rest;

import com.demo.rental_system_api.service.AuthService;
import com.demo.rental_system_api.web.dto.request.LoginRequest;
import com.demo.rental_system_api.web.dto.request.LoginWithTotpRequest;
import com.demo.rental_system_api.web.dto.request.SignupRequest;
import com.demo.rental_system_api.web.dto.response.utils.Response;
import com.demo.rental_system_api.web.dto.response.utils.ResponseUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RequiredArgsConstructor
@Slf4j
@RestController
@RequestMapping("/api/auth")
@CrossOrigin("*")
public class AuthResource {
    private final AuthService authService;

    @PostMapping("/signin")
    public ResponseEntity<Response> authenticateAccount(@Valid @RequestBody LoginRequest loginRequest) {
        return ResponseUtils.ok(authService.authenticateAccount(loginRequest));
    }

    @PostMapping("/signup")
    public ResponseEntity<Response> registerAccount(@Valid @RequestBody SignupRequest signupRequest) {
        authService.registerAccount(signupRequest);
        return ResponseUtils.created();
    }

    @GetMapping("/activate/{code}")
    public ResponseEntity<Response> activateEmailCode(@PathVariable String code) {
        authService.activateEmailCode(code);
        return ResponseUtils.created();
    }

    @GetMapping("/registerWithTotp")
    public ResponseEntity<Response> registerTotp() {
        return ResponseUtils.ok(authService.registerTotp());
    }

    @GetMapping("/register-totp/{code}")
    public ResponseEntity<Response> registerTotpCode(@PathVariable String code) {
        authService.registerTotpCode(code);
        return ResponseUtils.created();
    }

    @PostMapping("/active-totp")
    public ResponseEntity<Response> activeTotpCode(@RequestBody @Valid LoginWithTotpRequest request) {
        return ResponseUtils.created(authService.activeTotpCode(request));
    }
}
