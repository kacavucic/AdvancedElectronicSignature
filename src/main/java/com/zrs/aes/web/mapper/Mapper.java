package com.zrs.aes.web.mapper;

import com.zrs.aes.persistence.model.SigningSession;
import com.zrs.aes.response.DocumentResponse;
import com.zrs.aes.response.GetDocumentsResponse;
import com.zrs.aes.response.InitiateSigningSessionResponse;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class Mapper {
    public InitiateSigningSessionResponse toInitiateSigningSessionResponse(SigningSession signingSession) {
        String id = signingSession.getId();
        return new InitiateSigningSessionResponse(id);
    }

    public SigningSession toSigningSession(InitiateSigningSessionResponse initiateSigningSessionResponse) {
        return new SigningSession(initiateSigningSessionResponse.getId());
    }

    public GetDocumentsResponse toGetDocumentsResponse(List<SigningSession> signingSessions) {
        GetDocumentsResponse response = new GetDocumentsResponse();
        List<DocumentResponse> docs = new ArrayList<>();
        for (SigningSession ss : signingSessions) {
            DocumentResponse documentResponse = new DocumentResponse();
            documentResponse.setName(ss.getFileName());
            documentResponse.setAddedOn(ss.getAddedOn());
            documentResponse.setStatus(ss.isSigned());
            docs.add(documentResponse);
        }
        response.setDocuments(docs);
        return response;
    }

}
