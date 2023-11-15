package com.demo.rental_system_api.web.security.totpUtils;

public interface TotpManager {

    String generateSecret ();

    boolean validateCode (String code, String secret);

}
