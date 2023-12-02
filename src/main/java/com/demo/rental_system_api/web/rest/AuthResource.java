package com.demo.rental_system_api.web.rest;

import com.demo.rental_system_api.service.AuthService;
import com.demo.rental_system_api.web.dto.request.*;
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

    // E-mail api signup
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

    // TOTP api
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

    @GetMapping("/check-totp-register/{username}")
    public ResponseEntity<Response> checkTotpRegister(@PathVariable String username) {
        return ResponseUtils.ok(authService.checkTotpRegister(username));
    }

    // SMS API
    @PostMapping("/sms-authenticate")
    public ResponseEntity<Response> smsAuthenticate(@RequestBody @Valid SmsSenderRequest smsSenderRequest) {
        authService.smsAuthenticate(smsSenderRequest);
        return ResponseUtils.created();
    }

    @PostMapping("/sms-authenticate/active")
    public ResponseEntity<Response> activeSmsAuthenticate(@RequestBody @Valid LoginWithSmsRequest loginWithSmsRequest) {
        return ResponseUtils.ok(authService.activeSmsAuthenticate(loginWithSmsRequest));
    }

    // Email API authenticate
    @PostMapping("/email-authenticate")
    public ResponseEntity<Response> emailAuthenticate(@RequestBody @Valid EmailSenderRequest emailSenderRequest) {
        authService.emailAuthenticate(emailSenderRequest);
        return ResponseUtils.created();
    }

    @PostMapping("/email-authenticate/active")
    public ResponseEntity<Response> activeEmailAuthenticate(@RequestBody @Valid LoginWithEmailRequest loginWithEmailRequest) {
        return ResponseUtils.ok(authService.activeEmailAuthenticate(loginWithEmailRequest));
    }
}
