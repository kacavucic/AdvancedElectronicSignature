package com.zrs.aes.service.signingsession;

import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.zrs.aes.persistence.model.SigningSession;
import com.zrs.aes.response.SigningSessionResponse;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.UUID;
import javax.mail.MessagingException;
import javax.servlet.http.HttpServletRequest;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.springframework.core.io.Resource;
import org.springframework.web.multipart.MultipartFile;

/**
 * Manipulates a signing session details
 *
 * @author Katarina Vucic
 * @version 1.0
 */
public interface SigningSessionService {

  SigningSessionResponse getSigningSession(UUID signingSessionId);

  SigningSession findById(UUID signingSessionId);

  SigningSession save(SigningSession signingSession);

  List<SigningSessionResponse> getSigningSessions();

  SigningSessionResponse initiateSigningSession(MultipartFile file) throws IOException;

  SigningSessionResponse cancelSigningSession(UUID signingSessionId);

  SigningSessionResponse approveSigningSession(UUID signingSessionId, Boolean consent,
      Long certRequestedAt)
      throws GeneralSecurityException, IOException, OperatorCreationException, PKCSException, MessagingException;

  SigningSessionResponse resendCode(UUID signingSessionId, Long certRequestedAt)
      throws MessagingException, GeneralSecurityException, IOException, OperatorCreationException, PKCSException;

  void addSigningAttempt(SigningSession signingSession);

  void rejectSigning(SigningSession signingSession);

  SigningSessionResponse sign(UUID signingSessionId, String code,
      HttpServletRequest httpServletRequest)
      throws GeneralSecurityException, IOException, GeoIp2Exception;

  Resource getUnsignedDocument(UUID signingSessionId);

  Resource getSignedDocument(SigningSession signingSession);
}
