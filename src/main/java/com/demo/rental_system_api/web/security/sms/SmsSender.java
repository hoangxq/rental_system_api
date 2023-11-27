package com.demo.rental_system_api.web.security.sms;

import com.demo.rental_system_api.web.dto.request.SmsRequest;

public interface SmsSender {
    void sendSms(SmsRequest smsRequest);
}
