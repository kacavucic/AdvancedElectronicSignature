package com.zrs.aes.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ResendOtpResponse implements Serializable {
    private String id;
    private int otpAttempts;
    private Long suspendedUntil;
}
