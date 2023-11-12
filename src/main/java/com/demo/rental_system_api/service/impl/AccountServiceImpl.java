package com.demo.rental_system_api.service.impl;

import com.demo.rental_system_api.model.Account;
import com.demo.rental_system_api.repository.AccountRepository;
import com.demo.rental_system_api.service.AccountService;
import com.demo.rental_system_api.service.utils.MappingHelper;
import com.demo.rental_system_api.web.dto.request.CreateAccountRequest;
import com.demo.rental_system_api.web.exception.ServiceException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
public class AccountServiceImpl implements AccountService {
    private final AccountRepository accountRepository;
    private final MappingHelper mappingHelper;
    private final PasswordEncoder passwordEncoder;

    @Override
    public List<Account> getAllAccountProfiles() {
        return accountRepository.findAll();
    }

    @Override
    public Account createAccount(CreateAccountRequest createAccountRequest) {
        if (accountRepository.existsByUsernameOrEmail(createAccountRequest.getUsername(), createAccountRequest.getEmail()))
            throw new ServiceException("Email or username is existed in system", "err.api.email-username-is-existed");

        Account account = new Account();
        account.setUsername(createAccountRequest.getUsername());
        account.setEmail(createAccountRequest.getEmail());
        account.setPassword(passwordEncoder.encode(createAccountRequest.getPassword()));

        account.setRole(createAccountRequest.getRole());
        return accountRepository.save(account);
    }
}
