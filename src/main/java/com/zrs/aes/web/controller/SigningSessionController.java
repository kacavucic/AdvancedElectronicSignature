package com.zrs.aes.web.controller;


import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.zrs.aes.persistence.model.SigningSession;
import com.zrs.aes.service.signingSession.ISigningSessionService;
import com.zrs.aes.service.totp.TotpService;
import com.zrs.aes.web.dto.request.SignRequest;
import com.zrs.aes.web.dto.response.InitiateSigningSessionResponse;
import com.zrs.aes.web.dto.response.SignResponse;
import com.zrs.aes.web.mapper.Mapper;
import com.zrs.aes.web.validation.FileConstraint;
import lombok.AllArgsConstructor;
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

//    @GetMapping("/downloadFile/{fileName:.+}")
//    public ResponseEntity<Resource> downloadFile(@PathVariable String fileName, HttpServletRequest request) {
//        // Load file as Resource
//        Resource resource = storageService.loadFileAsResource(fileName);
//
//        // Try to determine file's content type
//        String contentType = null;
//        try {
//            contentType = request.getServletContext().getMimeType(resource.getFile().getAbsolutePath());
//        } catch (IOException ex) {
//            logger.info("Could not determine file type.");
//        }
//
//        // Fallback to the default content type if type could not be determined
//        if (contentType == null) {
//            contentType = "application/octet-stream";
//        }
//
//        return ResponseEntity.ok()
//                .contentType(MediaType.parseMediaType(contentType))
//                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + resource.getFilename() + "\"")
//                .body(resource);
//    }

}
