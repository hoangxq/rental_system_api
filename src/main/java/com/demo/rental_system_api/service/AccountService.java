package com.demo.rental_system_api.service;

import com.demo.rental_system_api.model.Account;
import com.demo.rental_system_api.web.dto.request.CreateAccountRequest;

import java.util.List;

public interface AccountService {
    List<Account> getAllAccountProfiles();

    Account createAccount(CreateAccountRequest createAccountRequest);
}
