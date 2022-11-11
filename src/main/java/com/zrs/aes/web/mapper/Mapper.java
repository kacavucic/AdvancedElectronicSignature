package com.zrs.aes.web.mapper;

import com.zrs.aes.persistence.model.SigningSession;
import com.zrs.aes.response.*;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class Mapper {
    public InitiateSigningSessionResponse toInitiateSigningSessionResponse(SigningSession signingSession) {
        String id = signingSession.getId();
        return new InitiateSigningSessionResponse(id);
    }

    public CancelSigningSessionResponse toCancelSigningSessionResponse(SigningSession signingSession) {
        String id = signingSession.getId();
        return new CancelSigningSessionResponse(id);
    }

    public StartSigningSessionResponse toStartSigningSessionResponse(SigningSession signingSession) {
        String id = signingSession.getId();
        return new StartSigningSessionResponse(id);
    }

    public ResendOtpResponse toResendOtpResponse(SigningSession signingSession) {
        String id = signingSession.getId();
        int otpAttempts = signingSession.getOtpAttempts();
        Long suspendedUntil = signingSession.getSuspendedUntil();
        return new ResendOtpResponse(id, otpAttempts, suspendedUntil);
    }

    public GetSigningSessionsResponse toGetSigningSessionsResponse(List<SigningSession> signingSessions) {
        GetSigningSessionsResponse response = new GetSigningSessionsResponse();
        List<SigningSessionResponse> sessions = new ArrayList<>();
        for (SigningSession ss : signingSessions) {
            SigningSessionResponse signingSessionResponse = new SigningSessionResponse();
            signingSessionResponse.setId(ss.getId());
            signingSessionResponse.setDocumentName(ss.getFileName());
            signingSessionResponse.setAddedOn(ss.getAddedOn());
            signingSessionResponse.setStatus(ss.getStatus().getStatusString());
            signingSessionResponse.setConsent(ss.isConsent());
            signingSessionResponse.setSignAttempts(ss.getSignAttempts());
            signingSessionResponse.setSuspendedUntil(ss.getSuspendedUntil());
            sessions.add(signingSessionResponse);
        }
        response.setSigningSessions(sessions);
        return response;
    }

}
