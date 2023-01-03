package com.zrs.aes.service.signingSession;

import com.zrs.aes.persistence.model.SigningSession;
import com.zrs.aes.request.ApproveSigningSessionRequest;
import org.springframework.core.io.Resource;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
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

    SigningSession approveSigningSession(SigningSession signingSession, ApproveSigningSessionRequest request,
                                         Map<String, Object> principalClaims)
            throws Exception;

    SigningSession resendCode(SigningSession signingSession, Map<String, Object> principalClaims, Long certRequestedAt)
            throws Exception;

    void addSigningAttempt(SigningSession signingSession);

    void rejectSigning(SigningSession signingSession);

    SigningSession sign(SigningSession signingSession, String code, String clientIp,
                        Map<String, Object> principalClaims)
            throws Exception;

    Resource getUnsignedDocument(SigningSession signingSession);

    Resource getSignedDocument(SigningSession signingSession);
}
