package com.zrs.aes.service.signingSession;

import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.zrs.aes.persistence.model.SigningSession;
import org.springframework.core.io.Resource;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.Map;
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

    SigningSession initiateSigningSession(MultipartFile file, Map<String, Object> principalClaims) throws IOException;

    SigningSession cancelSigningSession(SigningSession signingSession);

    SigningSession approveSigningSession(SigningSession signingSession, Boolean consent, Map<String, Object> principalClaims)
            throws MessagingException;

    SigningSession resendOtp(SigningSession signingSession, Map<String, Object> principalClaims) throws MessagingException;

    void addSigningAttempt(SigningSession signingSession);

    void rejectSigning(SigningSession signingSession);

    SigningSession sign(SigningSession signingSession, String otp, String clientIp, Map<String, Object> principalClaims)
            throws IOException, GeneralSecurityException, GeoIp2Exception;

    Resource getUnsignedDocument(SigningSession signingSession);

    Resource getSignedDocument(SigningSession signingSession);
}
