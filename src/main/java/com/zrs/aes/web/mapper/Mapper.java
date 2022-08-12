package com.zrs.aes.web.mapper;

import com.zrs.aes.persistence.model.SigningSession;
import com.zrs.aes.web.dto.response.InitiateSigningSessionResponse;
import org.springframework.stereotype.Component;

@Component
public class Mapper {
    public InitiateSigningSessionResponse toInitiateSigningSessionResponse(SigningSession signingSession) {
        String id = signingSession.getId();
        return new InitiateSigningSessionResponse(id);
    }

    public SigningSession toSigningSession(InitiateSigningSessionResponse initiateSigningSessionResponse) {
        return new SigningSession(initiateSigningSessionResponse.getId());
    }
}
