package com.zrs.aes.web.controller;


import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.zrs.aes.persistence.model.SigningSession;
import com.zrs.aes.service.signingSession.ISigningSessionService;
import com.zrs.aes.service.storage.IStorageService;
import com.zrs.aes.service.totp.TotpService;
import com.zrs.aes.web.dto.request.SignRequest;
import com.zrs.aes.web.dto.response.DownloadDocumentResponse;
import com.zrs.aes.web.dto.response.InitiateSigningSessionResponse;
import com.zrs.aes.web.dto.response.SignResponse;
import com.zrs.aes.web.mapper.Mapper;
import com.zrs.aes.web.validation.FileConstraint;
import lombok.AllArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Optional;


@RestController
@RequestMapping("signingSessions")
@AllArgsConstructor
@Validated
public class SigningSessionController {

    private TotpService totpService;
    private ISigningSessionService signingSessionService;
    private Mapper mapper;
    private IStorageService storageService;

    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<InitiateSigningSessionResponse> initiateSigningSession(@RequestParam("document") @FileConstraint MultipartFile file,
                                                                                 @AuthenticationPrincipal Jwt principal) throws MessagingException {

        SigningSession signingSession = signingSessionService.initiateSigningSession(file, principal);
        return new ResponseEntity<>(mapper.toInitiateSigningSessionResponse(signingSession), HttpStatus.CREATED);
    }

    @PostMapping(value = "{signingSessionId}/sign")
    public ResponseEntity<SignResponse> sign(@PathVariable String signingSessionId, @RequestBody SignRequest signRequest,
                                             @AuthenticationPrincipal Jwt principal,
                                             HttpServletRequest httpServletRequest)
            throws IOException, GeoIp2Exception, GeneralSecurityException {


        Optional<SigningSession> signingSessionOptional = signingSessionService.findById(signingSessionId);
        if (signingSessionOptional.isPresent()) {
            boolean codeVerified = totpService.verifyCode(signingSessionId, signRequest.getOtp());

            if (!codeVerified) {
                return new ResponseEntity<>(new SignResponse("Invalid or expired OTP"),
                        HttpStatus.BAD_REQUEST);
            } else {
                return new ResponseEntity<>(new SignResponse(signingSessionService.sign(signingSessionOptional.get(),
                        signRequest.getOtp(), httpServletRequest, principal)), HttpStatus.OK);
            }
        } else {
            return new ResponseEntity<>(new SignResponse("Signing session not found"),
                    HttpStatus.NOT_FOUND);
        }


    }

    @GetMapping(value = "{signingSessionId}/document")
    public ResponseEntity<?> downloadDocument(@PathVariable String signingSessionId) {
        Optional<SigningSession> signingSessionOptional = signingSessionService.findById(signingSessionId);
        if (signingSessionOptional.isPresent()) {
            if (signingSessionOptional.get().isSigned()) {
                Resource signedDocument = storageService.loadAsResource(signingSessionOptional.get().getSignedFileName());
                return ResponseEntity.ok()
                        .contentType(MediaType.APPLICATION_PDF)
                        .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + signedDocument.getFilename() + "\"")
                        .body(signedDocument);
            } else {
                return ResponseEntity.badRequest()
                        .contentType(MediaType.APPLICATION_JSON)
                        .body(new DownloadDocumentResponse("Document not signed"));
            }
        } else {
            return ResponseEntity.badRequest()
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(new DownloadDocumentResponse("Signing session not found"));
        }

    }

}
