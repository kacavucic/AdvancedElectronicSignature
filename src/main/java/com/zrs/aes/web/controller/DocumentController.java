package com.zrs.aes.web.controller;

import com.zrs.aes.persistence.model.SigningSession;
import com.zrs.aes.response.GetDocumentsResponse;
import com.zrs.aes.service.signingSession.ISigningSessionService;
import com.zrs.aes.web.mapper.Mapper;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("documents")
@AllArgsConstructor
public class DocumentController {
    private ISigningSessionService signingSessionService;
    private Mapper mapper;

    @CrossOrigin(origins = "http://localhost:3000")
    @GetMapping
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<GetDocumentsResponse> getDocuments(@AuthenticationPrincipal Jwt principal) {

        List<SigningSession> signingSessions = signingSessionService.findByUserId(principal.getClaimAsString("sub"));
        return new ResponseEntity<>(mapper.toGetDocumentsResponse(signingSessions), HttpStatus.OK);
    }
}
