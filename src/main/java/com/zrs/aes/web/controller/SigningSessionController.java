package com.zrs.aes.web.controller;


import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.zrs.aes.persistence.model.SigningSession;
import com.zrs.aes.request.SignRequest;
import com.zrs.aes.response.InitiateSigningSessionResponse;
import com.zrs.aes.response.SignResponse;
import com.zrs.aes.service.signingSession.ISigningSessionService;
import com.zrs.aes.service.storage.IStorageService;
import com.zrs.aes.service.totp.TotpService;
import com.zrs.aes.web.exception.InvalidOTPException;
import com.zrs.aes.web.exception.SigningSessionNotFoundException;
import com.zrs.aes.web.exception.UnsignedDocumentException;
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

    @CrossOrigin(origins = "http://localhost:3000")
    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.CREATED)
    public ResponseEntity<InitiateSigningSessionResponse> initiateSigningSession(@RequestParam("document") @FileConstraint MultipartFile file,
                                                                                 @AuthenticationPrincipal Jwt principal) throws MessagingException {

        SigningSession signingSession = signingSessionService.initiateSigningSession(file, principal);
        return new ResponseEntity<>(mapper.toInitiateSigningSessionResponse(signingSession), HttpStatus.CREATED);
    }

    @CrossOrigin(origins = "http://localhost:3000")
    @PostMapping(value = "{signingSessionId}/sign", consumes = MediaType.APPLICATION_JSON_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<SignResponse> sign(@PathVariable String signingSessionId, @RequestBody SignRequest signRequest,
                                             @AuthenticationPrincipal Jwt principal,
                                             HttpServletRequest httpServletRequest)
            throws IOException, GeoIp2Exception, GeneralSecurityException {


        Optional<SigningSession> signingSessionOptional = signingSessionService.findById(signingSessionId);
        if (signingSessionOptional.isPresent()) {
            boolean codeVerified = totpService.verifyCode(signingSessionId, signRequest.getOtp());

            if (!codeVerified) {
                throw new InvalidOTPException("Invalid or expired OTP");
//                return new ResponseEntity<>(new SignResponse("Invalid or expired OTP"),
//                        HttpStatus.BAD_REQUEST);
            } else {
                return new ResponseEntity<>(new SignResponse(signingSessionService.sign(signingSessionOptional.get(),
                        signRequest.getOtp(), httpServletRequest, principal)), HttpStatus.OK);
            }
        } else {
            throw new SigningSessionNotFoundException("Signing session not found");
//            return new ResponseEntity<>(new SignResponse("Signing session not found"),
//                    HttpStatus.NOT_FOUND);
        }
    }

    @CrossOrigin(origins = "http://localhost:3000", exposedHeaders = "X-Suggested-Filename")
    @GetMapping(value = "{signingSessionId}/document")
    public ResponseEntity<Resource> downloadDocument(@PathVariable String signingSessionId) {
        Optional<SigningSession> signingSessionOptional = signingSessionService.findById(signingSessionId);
        if (signingSessionOptional.isPresent()) {
            if (signingSessionOptional.get().isSigned()) {
                Resource signedDocument = storageService.loadAsResource(signingSessionOptional.get().getSignedFileName());

                HttpHeaders headers = new HttpHeaders();
                headers.add("X-Suggested-Filename", "signed_" + signingSessionOptional.get().getFileName());
                headers.add(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + signedDocument.getFilename() + "\"");

                return ResponseEntity.ok()
                        .contentType(MediaType.APPLICATION_PDF)
                        .headers(headers)
                        //.header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + signedDocument.getFilename() + "\"")
                        .body(signedDocument);
            } else {
                throw new UnsignedDocumentException("Document not signed");

            }
        } else {
            throw new SigningSessionNotFoundException("Signing session not found");
        }

    }

}
