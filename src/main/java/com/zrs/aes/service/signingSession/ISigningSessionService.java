package com.zrs.aes.service.signingSession;

import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.zrs.aes.persistence.model.SigningSession;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Manipulates a signing session details
 *
 * @author Katarina Vucic
 * @version 1.0
 */
public interface ISigningSessionService {


    SigningSession findById(UUID id);

    SigningSession save(SigningSession signingSession);

    List<SigningSession> findByUserId(UUID userId);

    // logic

    SigningSession initiateSigningSession(MultipartFile file, Jwt principal) throws MessagingException;

    SigningSession cancelSigningSession(SigningSession signingSession) throws MessagingException;

    SigningSession reviewSigningSession(SigningSession signingSession) throws MessagingException;

    SigningSession approveSigningSession(SigningSession signingSession, Boolean consent, Jwt principal)
            throws MessagingException;

    SigningSession resendOtp(SigningSession signingSession, Jwt principal) throws MessagingException;

    void addSigningAttempt(SigningSession signingSession);

    void rejectSigning(SigningSession signingSession);

    String sign(SigningSession signingSession, String otp, HttpServletRequest request, Jwt principal)
            throws IOException, GeoIp2Exception, GeneralSecurityException;
}
