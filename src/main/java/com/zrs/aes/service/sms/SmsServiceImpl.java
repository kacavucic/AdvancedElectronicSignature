package com.zrs.aes.service.sms;

import com.twilio.Twilio;
import com.twilio.rest.api.v2010.account.Message;
import com.twilio.type.PhoneNumber;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class SmsServiceImpl implements ISmsService {

    String sid;
    String token;

    public SmsServiceImpl(SmsProperties smsProperties) {
        this.sid = smsProperties.getTWILIO_ACCOUNT_SID();
        this.token = smsProperties.getTWILIO_AUTH_TOKEN();
    }

    @Override
    public void sendSigningSms(Map<String, Object> principalClaims, String code) {

        Twilio.init(sid, token);

        String phoneNumber = (String) principalClaims.get("mobile");
        String firstName = (String) principalClaims.get("given_name");
        String message =
                firstName + ", your code for document signing is " + code;

        Message.creator(new PhoneNumber(phoneNumber),
                new PhoneNumber("+16294682658"), message).create();

    }
}
