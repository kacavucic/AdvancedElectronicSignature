package com.zrs.aes.response;


import com.zrs.aes.persistence.model.Status;
import java.util.UUID;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class SigningSessionResponse {

  private UUID id;

  private UUID userId;

  private DocumentResponse document;

  private int resendAttempts;

  private int signAttempts;

  private Long suspendedUntil;

  private Boolean consent;

  private Status status;
}
