package com.demo.rental_system_api.service.impl;

import com.demo.rental_system_api.model.Account;
import com.demo.rental_system_api.model.SecretTotpKey;
import com.demo.rental_system_api.repository.AccountRepository;
import com.demo.rental_system_api.repository.SecretTotpKeyRepository;
import com.demo.rental_system_api.service.AuthService;
import com.demo.rental_system_api.service.utils.MailSenderService;
import com.demo.rental_system_api.service.utils.MappingHelper;
import com.demo.rental_system_api.web.dto.request.LoginRequest;
import com.demo.rental_system_api.web.dto.request.LoginWithTotpRequest;
import com.demo.rental_system_api.web.dto.request.SignupRequest;
import com.demo.rental_system_api.web.dto.response.JwtResponse;
import com.demo.rental_system_api.web.exception.EntityNotFoundException;
import com.demo.rental_system_api.web.exception.ServiceException;
import com.demo.rental_system_api.web.security.AuthoritiesConstants;
import com.demo.rental_system_api.web.security.SecurityUtils;
import com.demo.rental_system_api.web.security.jwt.JwtUtils;
import com.demo.rental_system_api.web.security.totpUtils.TotpManager;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final AccountRepository accountRepository;
    private final SecretTotpKeyRepository secretTotpKeyRepository;
    private final AuthenticationManager authenticationManager;
    private final JwtUtils jwtUtils;
    private final PasswordEncoder passwordEncoder;
    private final MappingHelper mappingHelper;
    private final MailSenderService mailSenderService;
    private final TotpManager totpManager;

    @Override
    public JwtResponse authenticateAccount(LoginRequest loginRequest) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jwtToken = jwtUtils.generateJwtToken(authentication);

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            List<String> authorities = userDetails.getAuthorities()
                    .stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());

            var secretTotp = secretTotpKeyRepository
                    .findByAccount_Username(userDetails.getUsername())
                    .orElse(null);

            if (secretTotp == null || !secretTotp.getActive())
                return new JwtResponse(jwtToken, "Bearer", userDetails.getUsername(), authorities.get(0));

            return new JwtResponse(loginRequest.getPassword(), "totp", userDetails.getUsername(), authorities.get(0));

        } catch (AuthenticationException authenticationException) {
            throw new ServiceException("Username or password is invalid", "err.authorize.unauthorized");
        }
    }

    @Override
    @Transactional
    public void registerAccount(SignupRequest signupRequest) {
        if (accountRepository.existsByUsernameOrEmail(signupRequest.getUsername(), signupRequest.getEmail()))
            throw new ServiceException("Email or username is existed in system", "err.api.email-username-is-existed");

        Account account = new Account();
        account.setUsername(signupRequest.getUsername());
        account.setEmail(signupRequest.getEmail());
        account.setPassword(passwordEncoder.encode(signupRequest.getPassword()));

        account.setActive(false);
        account.setActivationCode(UUID.randomUUID().toString());
        account.setRole(AuthoritiesConstants.ADMIN);
        accountRepository.save(account);

        String subject = "Activation code";
        String template = "mail-active";
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("firstName", account.getUsername());
        attributes.put("activeCode", account.getActivationCode());
        mailSenderService.sendMessageHtml(account.getEmail(), subject, template, attributes);
    }

    @Override
    public void activateEmailCode(String code) {
        Account account = accountRepository.findByActivationCode(code)
                .orElseThrow(() -> new ServiceException(
                        "Invalid active code",
                        "err.sys.invalid-active-code"
                ));
        account.setActivationCode(null);
        account.setActive(true);
        accountRepository.save(account);
    }

    @Override
    public String registerTotp() {
        var username = SecurityUtils.getCurrentUserLogin()
                .orElseThrow(() -> new ServiceException(
                        "unauthorization",
                        "err.sys.unauthorization"
                ));

        var account = accountRepository.findOneByUsername(username)
                .orElseThrow(() -> new EntityNotFoundException(
                        Account.class.getName(),
                        username
                ));

        var secret = secretTotpKeyRepository
                .findByAccount_Username(username)
                .orElseGet(() -> {
                    var newSecret = new SecretTotpKey();
                    newSecret.setSecret(totpManager.generateSecret());
                    newSecret.setAccount(account);
                    newSecret.setActive(false);
                    return secretTotpKeyRepository.save(newSecret);
                });
        return secret.getSecret();
    }

    @Override
    public void registerTotpCode(String code) {
        var username = SecurityUtils.getCurrentUserLogin()
                .orElseThrow(() -> new ServiceException(
                        "unauthorization",
                        "err.sys.unauthorization"
                ));

        var account = accountRepository.findOneByUsername(username)
                .orElseThrow(() -> new EntityNotFoundException(
                        Account.class.getName(),
                        username
                ));

        var secret = secretTotpKeyRepository
                .findByAccount_Username(username)
                .orElseThrow(() -> new ServiceException(
                        "unauthorization",
                        "err.sys.unauthorization"
                ));

        boolean codeMatched = totpManager.validateCode(code, secret.getSecret());

        if (!codeMatched) throw new ServiceException(
                "Code '" + code + "' is not matched",
                "err.sys.totp-code-not-matched");

        secret.setActive(true);
        secretTotpKeyRepository.save(secret);
    }

    @Override
    public JwtResponse activeTotpCode(LoginWithTotpRequest request) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
            String jwtToken = jwtUtils.generateJwtToken(authentication);

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            List<String> authorities = userDetails.getAuthorities()
                    .stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());

            var secretTotp = secretTotpKeyRepository
                    .findByAccount_Username(userDetails.getUsername())
                    .orElse(null);

            if (secretTotp == null || !secretTotp.getActive())
                return new JwtResponse(jwtToken, "Bearer", userDetails.getUsername(), authorities.get(0));

            boolean codeMatched = totpManager.validateCode(request.getActiveCode(), secretTotp.getSecret());

            if (!codeMatched) throw new ServiceException(
                    "Code '" + request.getActiveCode() + "' is not matched",
                    "err.sys.totp-code-not-matched");

            return new JwtResponse(jwtToken, "Bearer", userDetails.getUsername(), authorities.get(0));

        } catch (AuthenticationException authenticationException) {
            throw new ServiceException("Username or password is invalid", "err.authorize.unauthorized");
        }
    }
}
