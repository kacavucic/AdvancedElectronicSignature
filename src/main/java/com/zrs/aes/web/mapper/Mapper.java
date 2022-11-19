package com.zrs.aes.web.mapper;

import com.zrs.aes.persistence.model.SigningSession;
import com.zrs.aes.response.DocumentResponse;
import com.zrs.aes.response.SigningSessionResponse;
import com.zrs.aes.response.SigningSessionsResponse;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class Mapper {

    public SigningSessionResponse toSigningSessionResponse(SigningSession signingSession) {
        return createSigningSessionResponse(signingSession);
    }

    public SigningSessionsResponse toSigningSessionsResponse(List<SigningSession> signingSessions) {
        SigningSessionsResponse response = new SigningSessionsResponse();
        List<SigningSessionResponse> sessions = new ArrayList<>();
        for (SigningSession ss : signingSessions) {
            sessions.add(createSigningSessionResponse(ss));
        }
        response.setSigningSessions(sessions);
        return response;
    }

    private SigningSessionResponse createSigningSessionResponse(SigningSession signingSession) {
        SigningSessionResponse signingSessionResponse = SigningSessionResponse.builder()
                .id(signingSession.getId())
                .userId(signingSession.getUserId())
                .otpAttempts(signingSession.getOtpAttempts())
                .signAttempts(signingSession.getSignAttempts())
                .suspendedUntil(signingSession.getSuspendedUntil())
                .consent(signingSession.getConsent())
                .status(signingSession.getStatus())
                .build();

        DocumentResponse documentResponse = DocumentResponse.builder()
                .id(signingSession.getDocument().getId())
                .fileName(signingSession.getDocument().getFileName())
                .addedOn(signingSession.getDocument().getAddedOn())
                .signedFileName(signingSession.getDocument().getSignedFileName())
                .build();

        signingSessionResponse.setDocument(documentResponse);

        return signingSessionResponse;
    }

}
