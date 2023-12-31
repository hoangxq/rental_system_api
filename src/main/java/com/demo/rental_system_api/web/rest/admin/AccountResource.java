package com.demo.rental_system_api.web.rest.admin;

import com.demo.rental_system_api.service.AccountService;
import com.demo.rental_system_api.web.dto.request.CreateAccountRequest;
import com.demo.rental_system_api.web.dto.response.utils.ResponseUtils;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;

@RestController
@RequestMapping("/api/admin/accounts")
@CrossOrigin("*")
@RequiredArgsConstructor
public class AccountResource {
    private final AccountService accountService;

    @GetMapping
    public ResponseEntity<?> getAllAccount() {
        return ResponseUtils.ok(accountService.getAllAccountProfiles());
    }

    @PostMapping
    public ResponseEntity<?> createAccount(@Valid @RequestBody CreateAccountRequest createAccountRequest) {
        return ResponseUtils.ok(accountService.createAccount(createAccountRequest));
    }
}
