package com.zrs.aes.web.controller;


import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.zrs.aes.persistence.model.SigningSession;
import com.zrs.aes.persistence.model.Status;
import com.zrs.aes.request.ApproveSigningSessionRequest;
import com.zrs.aes.request.SignRequest;
import com.zrs.aes.response.*;
import com.zrs.aes.service.signingSession.ISigningSessionService;
import com.zrs.aes.service.storage.IStorageService;
import com.zrs.aes.service.totp.TotpService;
import com.zrs.aes.web.exception.*;
import com.zrs.aes.web.mapper.Mapper;
import com.zrs.aes.web.validation.FileConstraint;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import lombok.AllArgsConstructor;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Optional;
import java.util.UUID;


@RestController
@RequestMapping("signingSessions")
@AllArgsConstructor
@Validated
@SecurityRequirement(name = "security_auth")
public class SigningSessions {

    private static final String PATTERN_FORMAT = "dd-MM-yyyy hh:mm:ss";
    private TotpService totpService;
    private ISigningSessionService signingSessionService;
    private Mapper mapper;
    private IStorageService storageService;

    @CrossOrigin(origins = "http://localhost:3000")
    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.CREATED)
    public ResponseEntity<SigningSessionResponse> initiateSigningSession(
            @RequestParam("document") @FileConstraint MultipartFile file,
            @AuthenticationPrincipal Jwt principal) throws MessagingException {

        SigningSession signingSession = signingSessionService.initiateSigningSession(file, principal);
        return new ResponseEntity<>(mapper.toSigningSessionResponse(signingSession), HttpStatus.CREATED);
    }

    @CrossOrigin(origins = "http://localhost:3000")
    @PutMapping(value = "{signingSessionId}/cancel", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<CancelSigningSessionResponse> cancelSigningSession(@PathVariable UUID signingSessionId)
            throws MessagingException {

        Optional<SigningSession> signingSessionOptional = signingSessionService.findById(signingSessionId);
        if (signingSessionOptional.isPresent()) {
            if (signingSessionOptional.get().getStatus() != Status.PENDING) {
                throw new InvalidStatusException(
                        "Only pending signing sessions can be canceled.");
            }
            else {
                SigningSession signingSession =
                        signingSessionService.cancelSigningSession(signingSessionOptional.get());
                return new ResponseEntity<>(mapper.toCancelSigningSessionResponse(signingSession), HttpStatus.OK);
            }
        }
        else {
            throw new SigningSessionNotFoundException("Signing session not found.");
        }
    }

    @CrossOrigin(origins = "http://localhost:3000")
    @PutMapping(value = "{signingSessionId}/review", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<ReviewSigningSessionResponse> reviewSigningSession(@PathVariable UUID signingSessionId)
            throws MessagingException {

        Optional<SigningSession> signingSessionOptional = signingSessionService.findById(signingSessionId);
        if (signingSessionOptional.isPresent()) {
            if (signingSessionOptional.get().getStatus() != Status.CANCELED &&
                    signingSessionOptional.get().getStatus() != Status.PENDING) {
                throw new InvalidStatusException(
                        "Only pending or canceled signing sessions can be reviewed.");
            }
            else {
                SigningSession signingSession =
                        signingSessionService.reviewSigningSession(signingSessionOptional.get());
                return new ResponseEntity<>(mapper.toReviewSigningSessionResponse(signingSession), HttpStatus.OK);
            }
        }
        else {
            throw new SigningSessionNotFoundException("Signing session not found.");
        }
    }

    // TODO obrisati otp iz baze
    @CrossOrigin(origins = "http://localhost:3000")
    @PutMapping(value = "{signingSessionId}/approve", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<ApproveSigningSessionResponse> approveSigningSession(@PathVariable UUID signingSessionId,
                                                                               @RequestBody
                                                                                       ApproveSigningSessionRequest approveSigningSessionRequest,
                                                                               @AuthenticationPrincipal Jwt principal)
            throws MessagingException {

        Optional<SigningSession> signingSessionOptional = signingSessionService.findById(signingSessionId);
        if (signingSessionOptional.isPresent()) {
            if (signingSessionOptional.get().getStatus() != Status.PENDING &&
                    signingSessionOptional.get().getStatus() != Status.CANCELED) {
                throw new InvalidStatusException(
                        "Only pending or canceled signing sessions can be approved.");
            }
            else if (!approveSigningSessionRequest.getConsent()) {
                throw new ConsentRequiredException("Consent is required to approve signing session.");
            }
            else {
                SigningSession signingSession =
                        signingSessionService.approveSigningSession(signingSessionOptional.get(),
                                approveSigningSessionRequest.getConsent(), principal);
                return new ResponseEntity<>(mapper.toApproveSigningSessionResponse(signingSession), HttpStatus.OK);
            }
        }
        else {
            throw new SigningSessionNotFoundException("Signing session not found.");
        }
    }

    @CrossOrigin(origins = "http://localhost:3000")
    @PutMapping(value = "{signingSessionId}/resendOTP",
            produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<ResendOtpResponse> resendOtp(@PathVariable UUID signingSessionId,
                                                       @AuthenticationPrincipal Jwt principal)
            throws MessagingException {

        Optional<SigningSession> signingSessionOptional = signingSessionService.findById(signingSessionId);
        if (signingSessionOptional.isPresent()) {
            if (signingSessionOptional.get().getStatus() != Status.IN_PROGRESS) {
                throw new InvalidStatusException(
                        "OTP can be resent only for signing sessions in progress.");
            }
            else {
                SigningSession signingSession =
                        signingSessionService.resendOtp(signingSessionOptional.get(), principal);
                return new ResponseEntity<>(mapper.toResendOtpResponse(signingSession), HttpStatus.OK);
            }
        }
        else {
            throw new SigningSessionNotFoundException("Signing session not found.");
        }
    }

    // TODO logging
    @CrossOrigin(origins = "http://localhost:3000")
    @PostMapping(value = "{signingSessionId}/sign", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @Transactional(noRollbackFor = {InvalidStatusException.class, InvalidOTPException.class})
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<SignResponse> sign(@PathVariable UUID signingSessionId,
                                             @RequestBody SignRequest signRequest,
                                             @AuthenticationPrincipal Jwt principal,
                                             HttpServletRequest httpServletRequest)
            throws IOException, GeoIp2Exception, GeneralSecurityException {


        Optional<SigningSession> signingSessionOptional = signingSessionService.findById(signingSessionId);
        if (signingSessionOptional.isPresent()) {

            if (signingSessionOptional.get().getStatus() == Status.REJECTED) {
                throw new InvalidStatusException(
                        "Your signing session has been rejected due to entering invalid or expired OTP 3 times.");
            }

            if (signingSessionOptional.get().getStatus() != Status.IN_PROGRESS) {
                throw new InvalidStatusException(
                        "Document can be signed only for signing sessions in progress.");
            }

            if (signingSessionOptional.get().getSuspendedUntil() != null) {
                Instant instant = Instant.ofEpochSecond(signingSessionOptional.get().getSuspendedUntil());
                DateTimeFormatter formatter = DateTimeFormatter.ofPattern(PATTERN_FORMAT)
                        .withZone(ZoneId.systemDefault());
                throw new SigningSessionSuspendedException(
                        "Signing session is suspended until " + formatter.format(instant) +
                                " due to exceeding the number of allowed attempts to resend OTP.");
            }

            if (signingSessionOptional.get().getSignAttempts() == 3) {
                signingSessionService.rejectSigning(signingSessionOptional.get());
                throw new InvalidStatusException(
                        "Your signing session has been rejected due to entering invalid or expired OTP 3 times.");
            }
            else {
                boolean codeVerified =
                        totpService.verifyCode(signingSessionOptional.get().getOneTimePassword().getSecret(),
                                signRequest.getOtp());
                if (!codeVerified) {
                    signingSessionService.addSigningAttempt(signingSessionOptional.get());
                    throw new InvalidOTPException("Invalid or expired OTP.");
                }
                else {
                    return new ResponseEntity<>(
                            new SignResponse(signingSessionService.sign(signingSessionOptional.get(),
                                    signRequest.getOtp(), httpServletRequest, principal)), HttpStatus.OK);
                }
            }
        }
        else {
            throw new SigningSessionNotFoundException("Signing session not found.");
        }
    }

    @CrossOrigin(origins = "http://localhost:3000", exposedHeaders = "X-Suggested-Filename")
    @GetMapping(value = "{signingSessionId}/document")
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<Resource> downloadDocument(@PathVariable UUID signingSessionId) {
        Optional<SigningSession> signingSessionOptional = signingSessionService.findById(signingSessionId);
        if (signingSessionOptional.isPresent()) {
            if (signingSessionOptional.get().getStatus() == Status.SIGNED) {
                Resource signedDocument =
                        storageService.loadAsResource(signingSessionOptional.get().getDocument().getSignedFileName(),
                                true);

                HttpHeaders headers = new HttpHeaders();
                headers.add("X-Suggested-Filename",
                        "signed_" + signingSessionOptional.get().getDocument().getFileName());
                headers.add(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"" + signedDocument.getFilename() + "\"");

                return ResponseEntity.ok()
                        .contentType(MediaType.APPLICATION_PDF)
                        .headers(headers)
                        //.header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + signedDocument.getFilename() + "\"")
                        .body(signedDocument);
            }
            else {
                Resource unsignedDocument =
                        storageService.loadAsResource(signingSessionOptional.get().getDocument().getFileName(), false);

                HttpHeaders headers = new HttpHeaders();
                headers.add(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"" + unsignedDocument.getFilename() + "\"");

                return ResponseEntity.ok()
                        .contentType(MediaType.APPLICATION_PDF)
                        .headers(headers)
                        //.header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + signedDocument.getFilename() + "\"")
                        .body(unsignedDocument);
                // throw new UnsignedDocumentException("Document not signed");

            }
        }
        else {
            throw new SigningSessionNotFoundException("Signing session not found.");
        }

    }

    @CrossOrigin(origins = "http://localhost:3000")
    @GetMapping
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<GetSigningSessionsResponse> getSigningSessions(@AuthenticationPrincipal Jwt principal) {

        List<SigningSession> signingSessions = signingSessionService.findByUserId(UUID.fromString(principal.getClaimAsString("sub")));
        return new ResponseEntity<>(mapper.toGetSigningSessionsResponse(signingSessions), HttpStatus.OK);
    }

    @CrossOrigin(origins = "http://localhost:3000")
    @GetMapping(value = "{signingSessionId}")
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<SigningSessionResponse> getSigningSession(@PathVariable UUID signingSessionId) {

        Optional<SigningSession> signingSessionOptional = signingSessionService.findById(signingSessionId);
        if (signingSessionOptional.isPresent()) {
            return new ResponseEntity<>(mapper.toSigningSessionResponse(signingSessionOptional.get()), HttpStatus.OK);
        }
        else {
            throw new SigningSessionNotFoundException("Signing session not found.");
        }

    }

}
