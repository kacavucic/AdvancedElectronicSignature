package com.zrs.aes.persistence.model;

import lombok.Getter;
import lombok.Setter;
import org.springframework.stereotype.Component;

@Component
@Getter
@Setter
public class OTP {

    private String id;
    private String otp;
    private long timestamp;
}
