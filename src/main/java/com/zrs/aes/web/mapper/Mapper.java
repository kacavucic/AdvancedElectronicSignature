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

    public ReviewSigningSessionResponse toReviewSigningSessionResponse(SigningSession signingSession) {
        String id = signingSession.getId();
        return new ReviewSigningSessionResponse(id);
    }

    public ApproveSigningSessionResponse toApproveSigningSessionResponse(SigningSession signingSession) {
        String id = signingSession.getId();
        return new ApproveSigningSessionResponse(id);
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
            sessions.add(createSigningSessionResponse(ss));
        }
        response.setSigningSessions(sessions);
        return response;
    }


    public SigningSessionResponse toSigningSessionResponse(SigningSession signingSession) {
        return createSigningSessionResponse(signingSession);
    }

    private SigningSessionResponse createSigningSessionResponse(SigningSession signingSession) {
        SigningSessionResponse signingSessionResponse = new SigningSessionResponse();
        signingSessionResponse.setId(signingSession.getId());
        signingSessionResponse.setDocumentName(signingSession.getFileName());
        signingSessionResponse.setAddedOn(signingSession.getAddedOn());
        signingSessionResponse.setStatus(signingSession.getStatus().getStatusString());
        signingSessionResponse.setConsent(signingSession.isConsent());
        signingSessionResponse.setOtpAttempts(signingSession.getOtpAttempts());
        signingSessionResponse.setSignAttempts(signingSession.getSignAttempts());
        signingSessionResponse.setSuspendedUntil(signingSession.getSuspendedUntil());
        return signingSessionResponse;
    }

}
