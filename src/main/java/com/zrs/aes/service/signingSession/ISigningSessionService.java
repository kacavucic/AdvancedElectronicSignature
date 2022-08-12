package com.zrs.aes.service.signingSession;

import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.zrs.aes.persistence.model.SigningSession;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Optional;

/**
 * Manipulates a signing session details
 *
 * @author Katarina Vucic
 * @version 1.0
 */
public interface ISigningSessionService {


    Optional<SigningSession> findById(String id);


    SigningSession findByFilePath(String filepath);


    SigningSession save(SigningSession signingSession);

    // logic

    SigningSession initiateSigningSession(MultipartFile file, Jwt principal) throws MessagingException;

    String sign(SigningSession signingSession, String otp, HttpServletRequest request, Jwt principal) throws IOException, GeoIp2Exception, GeneralSecurityException;
}
