package com.zrs.aes.service.sms;

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class SmsServiceImpl implements SmsService {

    String sid;
    String token;

    public SmsServiceImpl(SmsProperties smsProperties) {
        this.sid = smsProperties.getTwilioAccountSid();
        this.token = smsProperties.getTwilioAuthToken();
    }

    @Override
    public void sendSigningSms(Map<String, Object> principalClaims, String code) {

        Twilio.init(sid, token);

        String phoneNumber = (String) principalClaims.get("mobile");
        String firstName = (String) principalClaims.get("given_name");
        String message =
                firstName + ", your code for document signing is " + code;

        Message.creator(new PhoneNumber(phoneNumber),
                new PhoneNumber("+12544428507"), message).create();

    }
}
