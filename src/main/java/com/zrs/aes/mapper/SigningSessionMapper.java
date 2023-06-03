package com.zrs.aes.mapper;

import com.zrs.aes.persistence.model.SigningSession;
import com.zrs.aes.response.DocumentResponse;
import com.zrs.aes.response.SigningSessionResponse;
import org.springframework.stereotype.Component;

@Component
public class SigningSessionMapper {

  public SigningSessionResponse toSigningSessionResponse(SigningSession signingSession) {
    SigningSessionResponse signingSessionResponse = SigningSessionResponse.builder()
        .id(signingSession.getId())
        .userId(signingSession.getUserId())
        .resendAttempts(signingSession.getResendAttempts())
        .signAttempts(signingSession.getSignAttempts())
        .suspendedUntil(signingSession.getSuspendedUntil())
        .consent(signingSession.getConsent())
        .status(signingSession.getStatus())
        .build();

    DocumentResponse documentResponse = DocumentResponse.builder()
        .id(signingSession.getDocument().getId())
        .fileName(signingSession.getDocument().getFileName())
        .addedAt(signingSession.getDocument().getAddedAt())
        .signedFileName(signingSession.getDocument().getSignedFileName())
        .build();

    signingSessionResponse.setDocument(documentResponse);

    return signingSessionResponse;
  }
}
