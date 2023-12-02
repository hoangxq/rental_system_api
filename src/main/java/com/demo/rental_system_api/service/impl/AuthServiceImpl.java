package com.demo.rental_system_api.service.impl;

import com.demo.rental_system_api.model.Account;
import com.demo.rental_system_api.model.SecretTotpKey;
import com.demo.rental_system_api.repository.AccountRepository;
import com.demo.rental_system_api.repository.SecretTotpKeyRepository;
import com.demo.rental_system_api.service.AuthService;
import com.demo.rental_system_api.service.utils.MailSenderService;
import com.demo.rental_system_api.service.utils.MappingHelper;
import com.demo.rental_system_api.web.dto.request.*;
import com.demo.rental_system_api.web.dto.response.JwtResponse;
import com.demo.rental_system_api.web.exception.EntityNotFoundException;
import com.demo.rental_system_api.web.exception.ServiceException;
import com.demo.rental_system_api.web.security.AuthoritiesConstants;
import com.demo.rental_system_api.web.security.SecurityUtils;
import com.demo.rental_system_api.web.security.jwt.JwtUtils;
import com.demo.rental_system_api.web.security.sms.SmsSender;
import com.demo.rental_system_api.web.security.totpUtils.TotpManager;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
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

import java.util.*;
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
    private final SmsSender smsSender;

    @Value("${security.sms.expiration}")
    private int smsActiveCodeExpirationMs;

    @Override
    public JwtResponse authenticateAccount(LoginRequest loginRequest) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            List<String> authorities = userDetails.getAuthorities()
                    .stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toList());

            var account = accountRepository
                    .findOneByUsername(userDetails.getUsername())
                    .orElseThrow(() -> new EntityNotFoundException(
                            Account.class.getName(),
                            userDetails.getUsername()
                    ));

            if (!account.isActive())
                throw new ServiceException(
                        "Account '" + userDetails.getUsername() + "' is not active",
                        "err.sys.account-is-not-active"
                );

            return new JwtResponse(loginRequest.getPassword(), "auth", userDetails.getUsername(), authorities.get(0));

        } catch (AuthenticationException authenticationException) {
            throw new ServiceException("Username or password is invalid", "err.authorize.unauthorized");
        }
    }

    // Register with email
    @Override
    @Transactional
    public void registerAccount(SignupRequest signupRequest) {
        if (accountRepository.existsByUsernameOrEmail(signupRequest.getUsername(), signupRequest.getEmail()))
            throw new ServiceException("Email or username is existed in system", "err.api.email-username-is-existed");

        Account account = new Account();
        account.setUsername(signupRequest.getUsername().trim());
        account.setEmail(signupRequest.getEmail().trim());
        account.setPassword(passwordEncoder.encode(signupRequest.getPassword().trim()));

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

    // TOTP service
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
                .findByAccount_Username(account.getUsername())
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

    // authenticate with totp
    @Override
    public JwtResponse activeTotpCode(LoginWithTotpRequest request) {
        var account = accountRepository
                .findByUsernameOrEmail(request.getUsername(), request.getUsername())
                .orElseThrow(() -> new EntityNotFoundException(
                        Account.class.getName(),
                        request.getUsername()
                ));

        var secretTotp = secretTotpKeyRepository
                .findByAccount_Username(account.getUsername())
                .orElse(null);

        if (secretTotp == null || !secretTotp.getActive())
            throw new ServiceException(
                    "You dont register authenticate with totp",
                    "err.sys.totp-not-register");

        boolean codeMatched = totpManager.validateCode(request.getActiveCode(), secretTotp.getSecret());

        if (!codeMatched) throw new ServiceException(
                "Code '" + request.getActiveCode() + "' is not matched",
                "err.sys.totp-code-not-matched");

        var jwtToken = jwtUtils.generateJwtTokenWithUsername(account.getUsername());

        return new JwtResponse(jwtToken, "Bearer", account.getUsername(), account.getRole().name());
    }

    // SMS service
    @Override
    @Transactional
    public void smsAuthenticate(SmsSenderRequest smsSenderRequest) {
        var account = accountRepository
                .findByUsernameOrEmail(smsSenderRequest.getUsername(), smsSenderRequest.getUsername())
                .orElseThrow(() -> new EntityNotFoundException(
                        Account.class.getName(),
                        smsSenderRequest.getUsername()
                ));

        var activeCode = generateRandomString();
        account.setSmsActiveCode(activeCode);
        account.setTimeCreateSmsActiveCode(new Date());
        accountRepository.save(account);

        String message = "Your active code is: " + activeCode;
        smsSender.sendSms(new SmsRequest(smsSenderRequest.getPhoneNumber(), message));
    }

    @Override
    public JwtResponse activeSmsAuthenticate(LoginWithSmsRequest request) {
        var account = accountRepository
                .findByUsernameOrEmail(request.getUsername(), request.getUsername())
                .orElseThrow(() -> new EntityNotFoundException(
                        Account.class.getName(),
                        request.getUsername()
                ));

        if (!account.getSmsActiveCode().equals(request.getActiveCode())) throw new ServiceException(
                "Code '" + request.getActiveCode() + "' is not matched",
                "err.sys.sms-code-not-matched");

        var checkTime = new Date(account.getTimeCreateSmsActiveCode().getTime() + smsActiveCodeExpirationMs);
        if (checkTime.before(new Date()))
            throw new ServiceException(
                    "Code '" + request.getActiveCode() + "' is expired",
                    "err.sys.sms-code-expired");

        var jwtToken = jwtUtils.generateJwtTokenWithUsername(account.getUsername());

        return new JwtResponse(jwtToken, "Bearer", account.getUsername(), account.getRole().name());
    }

    //Email authenticate
    @Override
    @Transactional
    public void emailAuthenticate(EmailSenderRequest emailSenderRequest) {
        var account = accountRepository
                .findByUsernameAndEmail(emailSenderRequest.getUsername(), emailSenderRequest.getEmail())
                .orElseThrow(() -> new EntityNotFoundException(
                        Account.class.getName(),
                        emailSenderRequest.getUsername()
                ));
        account.setActivationCode(UUID.randomUUID().toString());
        accountRepository.save(account);

        String subject = "Activation code";
        String template = "mail-active";
        Map<String, Object> attributes = new HashMap<>();
        attributes.put("firstName", account.getUsername());
        attributes.put("activeCode", account.getActivationCode());
        mailSenderService.sendMessageHtml(account.getEmail(), subject, template, attributes);
    }

    @Override
    public JwtResponse activeEmailAuthenticate(LoginWithEmailRequest loginWithEmailRequest) {
        var account = accountRepository
                .findOneByEmail(loginWithEmailRequest.getEmail())
                .orElseThrow(() -> new EntityNotFoundException(
                        Account.class.getName(),
                        loginWithEmailRequest.getEmail()
                ));

        if (!account.getActivationCode().equals(loginWithEmailRequest.getActiveCode())) throw new ServiceException(
                "Code '" + loginWithEmailRequest.getActiveCode() + "' is not matched",
                "err.sys.email-code-not-matched");

        var jwtToken = jwtUtils.generateJwtTokenWithUsername(account.getUsername());

        return new JwtResponse(jwtToken, "Bearer", account.getUsername(), account.getRole().name());
    }

    @Override
    public Boolean checkTotpRegister(String username) {
        var account = accountRepository
                .findByUsernameOrEmail(username, username)
                .orElseThrow(() -> new EntityNotFoundException(
                        Account.class.getName(),
                        username
                ));

        var secretTotp = secretTotpKeyRepository
                .findByAccount_Username(account.getUsername());

        return secretTotp.isPresent();
    }

    private static String generateRandomString() {
        var characters = "0123456789";
        Random random = new Random();
        StringBuilder stringBuilder = new StringBuilder(6);
        for (int i = 0; i < 6; i++) {
            int randomIndex = random.nextInt(characters.length());
            char randomChar = characters.charAt(randomIndex);
            stringBuilder.append(randomChar);
        }
        return stringBuilder.toString();
    }
}
