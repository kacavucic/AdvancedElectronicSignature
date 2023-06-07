package com.zrs.aes.service.signingsession;

import static com.zrs.aes.util.GenericMessage.ERROR_MESSAGE_APPROVE_FORBIDDEN;
import static com.zrs.aes.util.GenericMessage.ERROR_MESSAGE_CANCEL_FORBIDDEN;
import static com.zrs.aes.util.GenericMessage.ERROR_MESSAGE_CODE_RESEND_FORBIDDEN;
import static com.zrs.aes.util.GenericMessage.ERROR_MESSAGE_DOCUMENT_ALREADY_SIGNED;
import static com.zrs.aes.util.GenericMessage.ERROR_MESSAGE_DOWNLOAD_SIGNED_DOCUMENT_FORBIDDEN;
import static com.zrs.aes.util.GenericMessage.ERROR_MESSAGE_DOWNLOAD_UNSIGNED_DOCUMENT_FORBIDDEN;
import static com.zrs.aes.util.GenericMessage.ERROR_MESSAGE_INVALID_KEYSTORE_PASSWORD;
import static com.zrs.aes.util.GenericMessage.ERROR_MESSAGE_INVALID_USER;
import static com.zrs.aes.util.GenericMessage.ERROR_MESSAGE_SIGNING_SESSION_REJECTED;
import static com.zrs.aes.util.GenericMessage.ERROR_MESSAGE_SIGNING_SESSION_SUSPENDED;
import static com.zrs.aes.util.GenericMessage.ERROR_MESSAGE_SIGN_FORBIDDEN;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.signatures.SignatureUtil;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.zrs.aes.exception.customexceptions.DocumentAlreadySignedException;
import com.zrs.aes.exception.customexceptions.EntityNotFoundException;
import com.zrs.aes.exception.customexceptions.InvalidKeystorePassException;
import com.zrs.aes.exception.customexceptions.InvalidStatusException;
import com.zrs.aes.exception.customexceptions.InvalidUserException;
import com.zrs.aes.exception.customexceptions.SigningSessionSuspendedException;
import com.zrs.aes.mapper.SigningSessionMapper;
import com.zrs.aes.persistence.model.Document;
import com.zrs.aes.persistence.model.SigningSession;
import com.zrs.aes.persistence.model.Status;
import com.zrs.aes.persistence.repository.SigningSessionRepository;
import com.zrs.aes.response.SigningSessionResponse;
import com.zrs.aes.service.certificate.CertificateGenerationService;
import com.zrs.aes.service.email.EmailService;
import com.zrs.aes.service.location.GeoIPLocationService;
import com.zrs.aes.service.location.HttpUtils;
import com.zrs.aes.service.signing.SigningService;
import com.zrs.aes.service.sms.SmsService;
import com.zrs.aes.service.storage.StorageService;
import com.zrs.aes.util.AuthUtil;
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import javax.mail.MessagingException;
import javax.servlet.http.HttpServletRequest;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

@Service
@Transactional
@Slf4j
@AllArgsConstructor
public class SigningSessionServiceImpl implements SigningSessionService {

  private static final String PATTERN_FORMAT = "HH:mm:ss dd.MM.yyyy.";
  private final SigningSessionRepository signingSessionRepository;
  private final StorageService storageService;
  private final EmailService emailService;
  private final SmsService smsService;
  private final GeoIPLocationService locationService;
  private final SigningService signingService;
  private final CertificateGenerationService certificateGenerationService;
  private final SigningSessionMapper signingSessionMapper;

  @Override
  public SigningSessionResponse getSigningSession(UUID signingSessionId) {
    SigningSession signingSession = findById(signingSessionId);
    return signingSessionMapper.toSigningSessionResponse(signingSession);
  }

  @Override
  public SigningSession findById(UUID signingSessionId) {

    return signingSessionRepository
        .findById(signingSessionId)
        .orElseThrow(() -> new EntityNotFoundException(SigningSession.class,
                "signingSessionId", signingSessionId.toString()));
  }

  @Override
  public SigningSession save(SigningSession signingSession) {
    return signingSessionRepository.save(signingSession);
  }

  @Override
  public List<SigningSessionResponse> getSigningSessions() {
    UUID userId = UUID.fromString(AuthUtil.getPrincipalId());
    List<SigningSession> signingSessions = signingSessionRepository.findByUserId(userId);
    if (signingSessions.isEmpty()) {
      throw new EntityNotFoundException(SigningSession.class, "userId", userId.toString());
    }
    return signingSessions.stream().map(signingSessionMapper::toSigningSessionResponse).toList();
  }

  @Override
  public SigningSessionResponse initiateSigningSession(MultipartFile file) throws IOException {
    Map<String, Object> principalClaims = AuthUtil.getPrincipalClaims();

    Path filePath = storageService.store(file);
    String fileName = filePath.getFileName().toString();
    PdfDocument pdfDocument = new PdfDocument(new PdfReader(filePath.toString()));
    SignatureUtil signUtil = new SignatureUtil(pdfDocument);
    List<String> names = signUtil.getSignatureNames();
    if (!names.isEmpty()) {
      throw new DocumentAlreadySignedException(String
          .format(ERROR_MESSAGE_DOCUMENT_ALREADY_SIGNED, fileName));
    }

    SigningSession signingSession = SigningSession.builder()
        .userId(UUID.fromString((String) principalClaims.get("sub")))
        .status(Status.PENDING)
        .build();

    Document document = Document.builder()
        .signingSession(signingSession)
        .filePath(filePath.toAbsolutePath().toString())
        .fileName(fileName)
        .addedAt(Instant.now().getEpochSecond())
        .build();

    signingSession.setDocument(document);
    SigningSession initiatedSigningSession = save(signingSession);
    pdfDocument.close();
    return signingSessionMapper.toSigningSessionResponse(initiatedSigningSession);
  }

  @Override
  public SigningSessionResponse cancelSigningSession(UUID signingSessionId) {
    SigningSession signingSession = findById(signingSessionId);
    if (signingSession.getStatus() != Status.PENDING
        && signingSession.getStatus() != Status.IN_PROGRESS) {
      throw new InvalidStatusException(ERROR_MESSAGE_CANCEL_FORBIDDEN);
    } else {
      signingSession.setStatus(Status.CANCELED);
      SigningSession canceledSigningSession = save(signingSession);
      return signingSessionMapper.toSigningSessionResponse(canceledSigningSession);
    }
  }

  @Override
  public SigningSessionResponse approveSigningSession(UUID signingSessionId, Boolean consent, Long certRequestedAt)
      throws GeneralSecurityException, IOException, OperatorCreationException, PKCSException, MessagingException {
    SigningSession signingSession = findById(signingSessionId);
    Map<String, Object> principalClaims = AuthUtil.getPrincipalClaims();

    if (signingSession.getStatus() != Status.PENDING) {
      throw new InvalidStatusException(ERROR_MESSAGE_APPROVE_FORBIDDEN);
    }

    String keystorePassword = certificateGenerationService
        .generateUserCertificate(principalClaims, signingSession, certRequestedAt);
    signingSession.setConsent(true);
    signingSession.setStatus(Status.IN_PROGRESS);

    // TODO crl istice nakon 7 dana, moras pred odbranu novi da generises

    // TODO nema public key u bazi nakon potpisivanja WTFFFFFFFFFFF


    // smsService.sendSigningSms(principalClaims, keystorePassword);
    emailService.sendSigningEmail(principalClaims, keystorePassword);

    SigningSession approvedSigningSession = save(signingSession);
    return signingSessionMapper.toSigningSessionResponse(approvedSigningSession);
  }

  @Override
  @Transactional(noRollbackFor = SigningSessionSuspendedException.class)
  public SigningSessionResponse resendCode(UUID signingSessionId, Long certRequestedAt)
      throws MessagingException, GeneralSecurityException, IOException, OperatorCreationException, PKCSException {
    SigningSession signingSession = findById(signingSessionId);
    Map<String, Object> principalClaims = AuthUtil.getPrincipalClaims();

    if (signingSession.getStatus() != Status.IN_PROGRESS) {
      throw new InvalidStatusException(ERROR_MESSAGE_CODE_RESEND_FORBIDDEN);
    }

    if (signingSession.getSuspendedUntil() != null) {
      long currentTimestamp = Instant.now().getEpochSecond();

      if (currentTimestamp > signingSession.getSuspendedUntil()) {
        return generateAndSendCode(signingSession, 1, principalClaims, certRequestedAt);
      }

      Instant instant = Instant.ofEpochSecond(signingSession.getSuspendedUntil());
      DateTimeFormatter formatter = DateTimeFormatter.ofPattern(PATTERN_FORMAT)
          .withZone(ZoneId.systemDefault());
      throw new SigningSessionSuspendedException(String
          .format(ERROR_MESSAGE_SIGNING_SESSION_SUSPENDED, formatter.format(instant)));

    }

    if (signingSession.getResendAttempts() == 3) {
      long currentTimestamp = Instant.now().getEpochSecond();
      long plus30Minutes = currentTimestamp + TimeUnit.MINUTES.toSeconds(30);
      signingSession.setSuspendedUntil(plus30Minutes);
      save(signingSession);
      Instant instant = Instant.ofEpochSecond(plus30Minutes);
      DateTimeFormatter formatter = DateTimeFormatter.ofPattern(PATTERN_FORMAT)
          .withZone(ZoneId.systemDefault());
      throw new SigningSessionSuspendedException(String
          .format(ERROR_MESSAGE_SIGNING_SESSION_SUSPENDED, formatter.format(instant)));
    }
    return generateAndSendCode(signingSession,
        signingSession.getResendAttempts() + 1, principalClaims, certRequestedAt);
  }

  // TODO check cert validity before signing

  @Override
  public void addSigningAttempt(SigningSession signingSession) {
    signingSession.setSignAttempts(signingSession.getSignAttempts() + 1);
    save(signingSession);
  }

  @Override
  public void rejectSigning(SigningSession signingSession) {
    signingSession.setStatus(Status.REJECTED);
    save(signingSession);
  }

  private SigningSessionResponse generateAndSendCode(SigningSession signingSession,
      int resendAttempts,
      Map<String, Object> principalClaims,
      Long certRequestedAt)
      throws MessagingException, IOException, GeneralSecurityException, OperatorCreationException, PKCSException {
    // delete previous certificate
    storageService.deleteKeystore(signingSession.getCertificate().getSerialNumber() + ".pfx");

    String keystorePassword = certificateGenerationService
        .generateUserCertificate(principalClaims, signingSession, certRequestedAt);

    signingSession.setResendAttempts(resendAttempts);
    signingSession.setSuspendedUntil(null);

    // smsService.sendSigningSms(principalClaims, keystorePassword);
    emailService.sendSigningEmail(principalClaims, keystorePassword);

    SigningSession signingSessionWithResentCode = save(signingSession);
    return signingSessionMapper.toSigningSessionResponse(signingSessionWithResentCode);
  }

  @Override
  @Transactional(noRollbackFor = {InvalidStatusException.class, InvalidKeystorePassException.class})
  public SigningSessionResponse sign(UUID signingSessionId, String keystorePassword,
      HttpServletRequest httpServletRequest)
      throws GeneralSecurityException, IOException, GeoIp2Exception {
    String clientIp = HttpUtils.getRequestIPAddress(httpServletRequest);
    SigningSession signingSession = findById(signingSessionId);
    Map<String, Object> principalClaims = AuthUtil.getPrincipalClaims();

    /* TODO Proveri user id iz sesije sa SUB claim-om iz tokena
     * Kako se ovo gore moze zloupotrebiti:
     * User A zapocne sesiju i dodje do potpisivanja
     * User B se autentikuje i (nekako) ukrade podatke o sesiji usera A ali ne ukrade tokne
     * User B proba sa svojim tokenom da potpise sesiju korisnika A
     * Sistem ga zbog provere u gornjem t-o-d-o odbija
     */
    if (!signingSession.getUserId().toString().equals(principalClaims.get("sub"))) {
      throw new InvalidUserException(ERROR_MESSAGE_INVALID_USER);
    }
    if (signingSession.getStatus() == Status.REJECTED) {
      throw new InvalidStatusException(ERROR_MESSAGE_SIGNING_SESSION_REJECTED);
    }

    if (signingSession.getStatus() != Status.IN_PROGRESS) {
      throw new InvalidStatusException(ERROR_MESSAGE_SIGN_FORBIDDEN);
    }

    if (signingSession.getSuspendedUntil() != null) {
      Instant instant = Instant.ofEpochSecond(signingSession.getSuspendedUntil());
      DateTimeFormatter formatter = DateTimeFormatter.ofPattern(PATTERN_FORMAT)
          .withZone(ZoneId.systemDefault());
      throw new SigningSessionSuspendedException(String
          .format(ERROR_MESSAGE_SIGNING_SESSION_SUSPENDED, formatter.format(instant)));
    }

    if (signingSession.getSignAttempts() == 3) {
      rejectSigning(signingSession);
      throw new InvalidStatusException(ERROR_MESSAGE_SIGNING_SESSION_REJECTED);
    } else {
      boolean keystorePasswordVerified = certificateGenerationService
          .verifyKeystorePassword(signingSession, keystorePassword);
      if (!keystorePasswordVerified) {
        addSigningAttempt(signingSession);
        throw new InvalidKeystorePassException(ERROR_MESSAGE_INVALID_KEYSTORE_PASSWORD);
      } else {
        Path signedFilePath = signingService.sign(signingSession, clientIp, principalClaims,
            keystorePassword);
        signingSession.setStatus(Status.SIGNED);
        signingSession.getDocument().setSignedFilePath(signedFilePath.toAbsolutePath().toString());
        signingSession.getDocument().setSignedFileName(signedFilePath.getFileName().toString());
        SigningSession signedSigningSession = save(signingSession);
        return signingSessionMapper.toSigningSessionResponse(signedSigningSession);
      }
    }
  }


  @Override
  public Resource getUnsignedDocument(UUID signingSessionId) {
    SigningSession signingSession = findById(signingSessionId);
    if (signingSession.getStatus() != Status.SIGNED) {
      return storageService.loadAsResource(signingSession.getDocument().getFileName(), false);
    }
    throw new InvalidStatusException(ERROR_MESSAGE_DOWNLOAD_UNSIGNED_DOCUMENT_FORBIDDEN);
  }

  @Override
  public Resource getSignedDocument(SigningSession signingSession) {
    if (signingSession.getStatus() != Status.SIGNED) {
      throw new InvalidStatusException(ERROR_MESSAGE_DOWNLOAD_SIGNED_DOCUMENT_FORBIDDEN);
    }
    return storageService.loadAsResource(signingSession.getDocument().getSignedFileName(), true);
  }
}
