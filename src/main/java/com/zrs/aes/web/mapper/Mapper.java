package com.zrs.aes.web.mapper;

import com.zrs.aes.persistence.model.SigningSession;
import com.zrs.aes.response.*;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Component
public class Mapper {

    public SigningSessionResponse toSigningSessionResponse(SigningSession signingSession) {
        return createSigningSessionResponse(signingSession);
    }

    public CancelSigningSessionResponse toCancelSigningSessionResponse(SigningSession signingSession) {
        UUID id = signingSession.getId();
        return new CancelSigningSessionResponse(id);
    }

    public ReviewSigningSessionResponse toReviewSigningSessionResponse(SigningSession signingSession) {
        UUID id = signingSession.getId();
        return new ReviewSigningSessionResponse(id);
    }

    public ApproveSigningSessionResponse toApproveSigningSessionResponse(SigningSession signingSession) {
        UUID id = signingSession.getId();
        return new ApproveSigningSessionResponse(id);
    }

    public ResendOtpResponse toResendOtpResponse(SigningSession signingSession) {
        UUID id = signingSession.getId();
        int otpAttempts = signingSession.getOtpAttempts();
        Long suspendedUntil = signingSession.getSuspendedUntil();
        return new ResendOtpResponse(id, otpAttempts, suspendedUntil);
    }

    public GetSigningSessionsResponse toGetSigningSessionsResponse(List<SigningSession> signingSessions) {
        GetSigningSessionsResponse response = new GetSigningSessionsResponse();
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
