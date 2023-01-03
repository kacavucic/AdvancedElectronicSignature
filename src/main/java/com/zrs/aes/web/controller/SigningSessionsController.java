package com.zrs.aes.web.controller;


import com.zrs.aes.persistence.model.SigningSession;
import com.zrs.aes.request.ApproveSigningSessionRequest;
import com.zrs.aes.request.SignRequest;
import com.zrs.aes.response.SigningSessionResponse;
import com.zrs.aes.response.SigningSessionsResponse;
import com.zrs.aes.service.location.HttpUtils;
import com.zrs.aes.service.signingSession.ISigningSessionService;
import com.zrs.aes.service.sms.ISmsService;
import com.zrs.aes.web.error.ApiError;
import com.zrs.aes.web.mapper.Mapper;
import com.zrs.aes.web.validation.FileConstraint;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.parameters.RequestBody;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
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
import javax.validation.Valid;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;


@RestController
@RequestMapping("signingSessions")
@AllArgsConstructor
@Validated
@Tag(name = "signing-sessions")
public class SigningSessionsController {

    private ISigningSessionService signingSessionService;
    private ISmsService smsService;
    private Mapper mapper;

    @Operation(summary = "Initiates signing session",
            description = "Initiates signing session with provided PDF document to be signed." +
                    " Only PDF file format is supported. Empty, malformed, or already signed files are not allowed." +
                    " Maximum file size of a document is 10MB." +
                    " Once signing session is initiated its status becomes 'Pending'.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Signing session initiated"),
            @ApiResponse(responseCode = "405", description = "Method Not Allowed",
                    content = {@Content(schema = @Schema(implementation = ApiError.class))}),
            @ApiResponse(responseCode = "415", description = "Unsupported Media Type",
                    content = {@Content(schema = @Schema(implementation = ApiError.class))})})
    @CrossOrigin(origins = "http://localhost:3000")
    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE, produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.CREATED)
    public ResponseEntity<SigningSessionResponse> initiateSigningSession(
            @RequestBody(description = "PDF document to be signed")
            @RequestParam(name = "document") @FileConstraint MultipartFile file,
            @AuthenticationPrincipal Jwt principal) throws IOException {
        Map<String, Object> principalClaims = principal.getClaims();
        SigningSession initiatedSigningSession = signingSessionService.initiateSigningSession(file, principalClaims);
        return new ResponseEntity<>(mapper.toSigningSessionResponse(initiatedSigningSession), HttpStatus.CREATED);
    }


    @Operation(summary = "Cancels signing session",
            description = "Cancels signing session." +
                    " Only signing sessions with status 'Pending' or 'In Progress' can be canceled." +
                    " Once signing session is canceled its status becomes 'Canceled'.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Signing session canceled"),
            @ApiResponse(responseCode = "405", description = "Method Not Allowed",
                    content = {@Content(schema = @Schema(implementation = ApiError.class))}),
            @ApiResponse(responseCode = "415", description = "Unsupported Media Type",
                    content = {@Content(schema = @Schema(implementation = ApiError.class))})})
    @CrossOrigin(origins = "http://localhost:3000")
    @PutMapping(value = "{signingSessionId}/cancel", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<SigningSessionResponse> cancelSigningSession(
            @Parameter(description = "ID of signing session to be canceled") @PathVariable UUID signingSessionId) {
        SigningSession signingSession = signingSessionService.findById(signingSessionId);
        SigningSession canceledSigningSession = signingSessionService.cancelSigningSession(signingSession);
        return new ResponseEntity<>(mapper.toSigningSessionResponse(canceledSigningSession), HttpStatus.OK);
    }


    // TODO obrisati otp iz baze


    @Operation(summary = "Approves signing session",
            description = "Approves signing session by updating its field 'consent'" +
                    " which must be set to 'true' in order for approval to be successful." +
                    " Upon successful approval code is generated and sent to authenticated user's email address" +
                    " and is later used as input for signing process." +
                    " Only signing sessions with status 'Pending' can be approved." +
                    " Once signing session is approved its status becomes 'In Progress'.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Signing session approved"),
            @ApiResponse(responseCode = "400", description = "Not Found",
                    content = {@Content(schema = @Schema(implementation = ApiError.class))}),
            @ApiResponse(responseCode = "405", description = "Method Not Allowed",
                    content = {@Content(schema = @Schema(implementation = ApiError.class))}),
            @ApiResponse(responseCode = "415", description = "Unsupported Media Type",
                    content = {@Content(schema = @Schema(implementation = ApiError.class))}),
            @ApiResponse(responseCode = "500", description = "Internal Server Error",
                    content = {@Content(schema = @Schema(implementation = ApiError.class))})})
    @CrossOrigin(origins = "http://localhost:3000")
    @PutMapping(value = "{signingSessionId}/approve", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<SigningSessionResponse> approveSigningSession(
            @Parameter(description = "ID of signing session to be approved") @PathVariable UUID signingSessionId,
            @RequestBody(
                    description = "Consent used for approving signing session")
            @Valid
            @org.springframework.web.bind.annotation.RequestBody
                    ApproveSigningSessionRequest request,
            @AuthenticationPrincipal Jwt principal)
            throws Exception {
        request.setCertRequestedAt(Instant.now().getEpochSecond());
        SigningSession signingSession = signingSessionService.findById(signingSessionId);
        Map<String, Object> principalClaims = principal.getClaims();
        SigningSession approvedSigningSession =
                signingSessionService.approveSigningSession(signingSession, request, principalClaims);
        return new ResponseEntity<>(mapper.toSigningSessionResponse(approvedSigningSession), HttpStatus.OK);
    }


    @Operation(summary = "Resends code associated with signing session",
            description =
                    "Generates new code, updates it for associated signing session and sends it to authenticated user's email address." +
                            " If code hasn't been successfully sent," +
                            " authenticated users are able to request for new code to be sent to their email address." +
                            " The maximum allowed attempts to request for a new code per signing session is 3," +
                            " after which signing session becomes suspended for half an hour." +
                            " During suspension resending code and signing of a document is disabled." +
                            " Only signing sessions with status 'In Progress' can have their code resent." +
                            " Upon resending code status of signing session stays 'In Progress'.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Code resent"),
            @ApiResponse(responseCode = "405", description = "Method Not Allowed",
                    content = {@Content(schema = @Schema(implementation = ApiError.class))}),
            @ApiResponse(responseCode = "415", description = "Unsupported Media Type",
                    content = {@Content(schema = @Schema(implementation = ApiError.class))})})
    @CrossOrigin(origins = "http://localhost:3000")
    @PutMapping(value = "{signingSessionId}/resendCode",
            produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<SigningSessionResponse> resendCode(
            @Parameter(description = "ID of signing session associated with code to be resent") @PathVariable
                    UUID signingSessionId,
            @AuthenticationPrincipal Jwt principal)
            throws Exception {
        Long certRequestedAt = Instant.now().getEpochSecond();
        Map<String, Object> principalClaims = principal.getClaims();
        SigningSession signingSession = signingSessionService.findById(signingSessionId);
        SigningSession signingSessionWithResentCode =
                signingSessionService.resendCode(signingSession, principalClaims, certRequestedAt);
        return new ResponseEntity<>(mapper.toSigningSessionResponse(signingSessionWithResentCode), HttpStatus.OK);
    }


    // TODO logging

    @Operation(summary = "Signs document associated with signing session",
            description = "Signs document associated with signing session" +
                    " and stores the signed document on server." +
                    " Requires valid code to be provided in order for signing process to be successful." +
                    " The maximum allowed attempts to sign with invalid code is 3, after which status of signing session becomes 'Rejected'" +
                    " Only signing sessions with status 'In Progress' can have their document be signed." +
                    " Once document associated with signing session is signed its status becomes 'Signed'.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Document signed"),
            @ApiResponse(responseCode = "405", description = "Method Not Allowed",
                    content = {@Content(schema = @Schema(implementation = ApiError.class))}),
            @ApiResponse(responseCode = "415", description = "Unsupported Media Type",
                    content = {@Content(schema = @Schema(implementation = ApiError.class))})})
    @CrossOrigin(origins = "http://localhost:3000")
    @PutMapping(value = "{signingSessionId}/sign", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<SigningSessionResponse> sign(
            @Parameter(description = "ID of signing session associated with document to be signed")
            @PathVariable UUID signingSessionId,
            @RequestBody(
                    description = "Valid code which was sent to authenticated user's email address upon approval of signing session")
            @Valid @org.springframework.web.bind.annotation.RequestBody
                    SignRequest signRequest,
            @AuthenticationPrincipal Jwt principal,
            HttpServletRequest httpServletRequest)
            throws Exception {

        SigningSession signingSession = signingSessionService.findById(signingSessionId);
        Map<String, Object> principalClaims = principal.getClaims();
        String clientIp = HttpUtils.getRequestIPAddress(httpServletRequest);
        SigningSession signedSigningSession =
                signingSessionService.sign(signingSession, signRequest.getCode(), clientIp, principalClaims);
        return new ResponseEntity<>(mapper.toSigningSessionResponse(signedSigningSession), HttpStatus.OK);
    }


    @Operation(summary = "Gets unsigned document",
            description = "Gets unsigned document associated with signing session.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Unsigned document found"),
            @ApiResponse(responseCode = "405", description = "Method Not Allowed",
                    content = {@Content(schema = @Schema(implementation = ApiError.class))}),
            @ApiResponse(responseCode = "415", description = "Unsupported Media Type",
                    content = {@Content(schema = @Schema(implementation = ApiError.class))})})
    @CrossOrigin(origins = "http://localhost:3000", exposedHeaders = "X-Suggested-Filename")
    @GetMapping(value = "{signingSessionId}/unsignedDocument")
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<Resource> getUnsignedDocument(
            @Parameter(description = "ID of signing session associated with unsigned document to be returned")
            @PathVariable UUID signingSessionId) {
        SigningSession signingSession = signingSessionService.findById(signingSessionId);
        Resource unsignedDocument = signingSessionService.getUnsignedDocument(signingSession);

        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.CONTENT_DISPOSITION,
                "attachment; filename=\"" + unsignedDocument.getFilename() + "\"");

        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_PDF)
                .headers(headers)
                //.header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + signedDocument.getFilename() + "\"")
                .body(unsignedDocument);
    }


    @Operation(summary = "Gets signed document",
            description = "Gets signed document associated with signing session.")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Signed document found"),
            @ApiResponse(responseCode = "405", description = "Method Not Allowed",
                    content = {@Content(schema = @Schema(implementation = ApiError.class))}),
            @ApiResponse(responseCode = "415", description = "Unsupported Media Type",
                    content = {@Content(schema = @Schema(implementation = ApiError.class))})})
    @CrossOrigin(origins = "http://localhost:3000", exposedHeaders = "X-Suggested-Filename")
    @GetMapping(value = "{signingSessionId}/signedDocument")
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<Resource> getSignedDocument(
            @Parameter(description = "ID of signing session associated with signed document to be returned")
            @PathVariable UUID signingSessionId) {
        SigningSession signingSession = signingSessionService.findById(signingSessionId);
        Resource signedDocument = signingSessionService.getSignedDocument(signingSession);

        HttpHeaders headers = new HttpHeaders();
        headers.add("X-Suggested-Filename",
                "signed_" + signingSession.getDocument().getFileName());
        headers.add(HttpHeaders.CONTENT_DISPOSITION,
                "attachment; filename=\"" + signedDocument.getFilename() + "\"");

        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_PDF)
                .headers(headers)
                //.header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + signedDocument.getFilename() + "\"")
                .body(signedDocument);
    }


    @Operation(summary = "Gets all signing sessions owned by authenticated user",
            description = "Returns list of all signing sessions based on authenticated user's ID")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Signing sessions found"),
            @ApiResponse(responseCode = "405", description = "Method Not Allowed",
                    content = {@Content(schema = @Schema(implementation = ApiError.class))}),
            @ApiResponse(responseCode = "415", description = "Unsupported Media Type",
                    content = {@Content(schema = @Schema(implementation = ApiError.class))})})
    @CrossOrigin(origins = "http://localhost:3000")
    @GetMapping(produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<SigningSessionsResponse> getSigningSessions(@AuthenticationPrincipal Jwt principal) {
        List<SigningSession> signingSessions =
                signingSessionService.findByUserId(UUID.fromString(principal.getClaimAsString("sub")));
        return new ResponseEntity<>(mapper.toSigningSessionsResponse(signingSessions), HttpStatus.OK);
    }

    @Operation(summary = "Gets signing session by its ID",
            description = "Returns signing session information based on provided signing session ID")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Signing session found"),
            @ApiResponse(responseCode = "405", description = "Method Not Allowed",
                    content = {@Content(schema = @Schema(implementation = ApiError.class))}),
            @ApiResponse(responseCode = "415", description = "Unsupported Media Type",
                    content = {@Content(schema = @Schema(implementation = ApiError.class))})})
    @CrossOrigin(origins = "http://localhost:3000")
    @GetMapping(value = "{signingSessionId}", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseStatus(HttpStatus.OK)
    public ResponseEntity<SigningSessionResponse> getSigningSession(
            @Parameter(description = "ID of signing session to be returned")
            @PathVariable UUID signingSessionId) {
        SigningSession signingSession = signingSessionService.findById(signingSessionId);
        return new ResponseEntity<>(mapper.toSigningSessionResponse(signingSession), HttpStatus.OK);
    }

}
