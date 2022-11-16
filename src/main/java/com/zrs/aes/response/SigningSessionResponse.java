package com.zrs.aes.response;


import com.zrs.aes.persistence.model.Document;
import com.zrs.aes.persistence.model.OneTimePassword;
import com.zrs.aes.persistence.model.Status;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class SigningSessionResponse {

    private UUID id;

    private UUID userId;

    private DocumentResponse document;

    private int otpAttempts;

    private int signAttempts;

    private Long suspendedUntil;

    private Boolean consent;

    private Status status;
}
