package com.zrs.aes.controller;


import static org.springframework.http.HttpHeaders.CONTENT_DISPOSITION;
import static org.springframework.http.HttpStatus.CREATED;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.http.MediaType.APPLICATION_PDF;
import static org.springframework.http.MediaType.MULTIPART_FORM_DATA_VALUE;

import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.zrs.aes.persistence.model.SigningSession;
import com.zrs.aes.request.ApproveSigningSessionRequest;
import com.zrs.aes.request.SignRequest;
import com.zrs.aes.response.SigningSessionResponse;
import com.zrs.aes.service.signingsession.SigningSessionService;
import com.zrs.aes.validation.FileConstraint;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import javax.mail.MessagingException;
import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import lombok.AllArgsConstructor;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;


@RestController
@RequestMapping("signingSessions")
@AllArgsConstructor
@Validated
public class SigningSessionController {

  private final SigningSessionService signingSessionService;

  @CrossOrigin(origins = "http://localhost:3000")
  @PostMapping(consumes = MULTIPART_FORM_DATA_VALUE, produces = APPLICATION_JSON_VALUE)
  public ResponseEntity<SigningSessionResponse> initiateSigningSession(
      @RequestParam(name = "document") @FileConstraint
      MultipartFile file) throws IOException {
    SigningSessionResponse initiatedSigningSession = signingSessionService.initiateSigningSession(
        file);
    return new ResponseEntity<>(initiatedSigningSession, CREATED);
  }

  @CrossOrigin(origins = "http://localhost:3000")
  @PutMapping(value = "{signingSessionId}/cancel", produces = APPLICATION_JSON_VALUE)
  public ResponseEntity<SigningSessionResponse> cancelSigningSession(
      @PathVariable UUID signingSessionId) {
    SigningSessionResponse canceledSigningSession = signingSessionService.cancelSigningSession(
        signingSessionId);
    return new ResponseEntity<>(canceledSigningSession, OK);
  }

  // TODO obrisati otp iz baze

  @CrossOrigin(origins = "http://localhost:3000")
  @PutMapping(value = "{signingSessionId}/approve", consumes = APPLICATION_JSON_VALUE, produces = APPLICATION_JSON_VALUE)
  public ResponseEntity<SigningSessionResponse> approveSigningSession(
      @PathVariable UUID signingSessionId,
      @Valid
      @RequestBody ApproveSigningSessionRequest request)
      throws GeneralSecurityException, IOException, OperatorCreationException, PKCSException, MessagingException {
    request.setCertRequestedAt(Instant.now().getEpochSecond());
    SigningSessionResponse approvedSigningSession = signingSessionService
        .approveSigningSession(signingSessionId, request.getConsent(),
            request.getCertRequestedAt());
    return new ResponseEntity<>(approvedSigningSession, OK);
  }

  @CrossOrigin(origins = "http://localhost:3000")
  @PutMapping(value = "{signingSessionId}/resendCode", produces = APPLICATION_JSON_VALUE)
  public ResponseEntity<SigningSessionResponse> resendCode(@PathVariable UUID signingSessionId)
      throws MessagingException, GeneralSecurityException, IOException, OperatorCreationException, PKCSException {
    SigningSessionResponse signingSessionWithResentCode = signingSessionService
        .resendCode(signingSessionId, Instant.now().getEpochSecond());
    return new ResponseEntity<>(signingSessionWithResentCode, OK);
  }

  // TODO logging

  @CrossOrigin(origins = "http://localhost:3000")
  @PutMapping(value = "{signingSessionId}/sign", consumes = APPLICATION_JSON_VALUE, produces = APPLICATION_JSON_VALUE)
  public ResponseEntity<SigningSessionResponse> sign(@PathVariable UUID signingSessionId,
      @Valid @RequestBody SignRequest signRequest,
      HttpServletRequest httpServletRequest)
      throws GeneralSecurityException, IOException, GeoIp2Exception {
    SigningSessionResponse signedSigningSession = signingSessionService
        .sign(signingSessionId, signRequest.getCode(), httpServletRequest);
    return new ResponseEntity<>(signedSigningSession, OK);
  }

  @CrossOrigin(origins = "http://localhost:3000", exposedHeaders = "X-Suggested-Filename")
  @GetMapping(value = "{signingSessionId}/unsignedDocument")
  public ResponseEntity<Resource> getUnsignedDocument(@PathVariable UUID signingSessionId) {
    Resource unsignedDocument = signingSessionService.getUnsignedDocument(signingSessionId);

    HttpHeaders headers = new HttpHeaders();
    headers.add(CONTENT_DISPOSITION,
        "attachment; filename=\"" + unsignedDocument.getFilename() + "\"");

    return ResponseEntity.ok()
        .contentType(APPLICATION_PDF)
        .headers(headers)
        .body(unsignedDocument);
  }

  @CrossOrigin(origins = "http://localhost:3000", exposedHeaders = "X-Suggested-Filename")
  @GetMapping(value = "{signingSessionId}/signedDocument")
  public ResponseEntity<Resource> getSignedDocument(@PathVariable UUID signingSessionId) {
    SigningSession signingSession = signingSessionService.findById(signingSessionId);
    Resource signedDocument = signingSessionService.getSignedDocument(signingSession);

    HttpHeaders headers = new HttpHeaders();
    headers.add("X-Suggested-Filename", "signed_" + signingSession.getDocument().getFileName());
    headers.add(CONTENT_DISPOSITION,
        "attachment; filename=\"" + signedDocument.getFilename() + "\"");

    return ResponseEntity.ok()
        .contentType(APPLICATION_PDF)
        .headers(headers)
        .body(signedDocument);
  }

  @CrossOrigin(origins = "http://localhost:3000")
  @GetMapping(produces = APPLICATION_JSON_VALUE)
  public ResponseEntity<List<SigningSessionResponse>> getSigningSessions() {
    List<SigningSessionResponse> signingSessions = signingSessionService.getSigningSessions();
    return new ResponseEntity<>(signingSessions, OK);
  }

  @CrossOrigin(origins = "http://localhost:3000")
  @GetMapping(value = "{signingSessionId}", produces = APPLICATION_JSON_VALUE)
  public ResponseEntity<SigningSessionResponse> getSigningSession(
      @PathVariable UUID signingSessionId) {
    SigningSessionResponse signingSession = signingSessionService.getSigningSession(
        signingSessionId);
    return new ResponseEntity<>(signingSession, OK);
  }
}
