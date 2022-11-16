package com.zrs.aes.response;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.UUID;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class ResendOtpResponse implements Serializable {
    private UUID id;
    private int otpAttempts;
    private Long suspendedUntil;
}
