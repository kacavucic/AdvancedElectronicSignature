package com.zrs.aes.service.signingSession;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.signatures.SignatureUtil;
import com.zrs.aes.persistence.model.Document;
import com.zrs.aes.persistence.model.SigningSession;
import com.zrs.aes.persistence.model.Status;
import com.zrs.aes.persistence.repository.ISigningSessionRepository;
import com.zrs.aes.request.ApproveSigningSessionRequest;
import com.zrs.aes.service.certificate.CertificateGenerationService;
import com.zrs.aes.service.email.IEmailService;
import com.zrs.aes.service.location.GeoIPLocationService;
import com.zrs.aes.service.signing.SigningService;
import com.zrs.aes.service.sms.ISmsService;
import com.zrs.aes.service.storage.IStorageService;
import com.zrs.aes.web.customexceptions.*;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Service
@Transactional
@Slf4j
@AllArgsConstructor
public class SigningSessionServiceImpl implements ISigningSessionService {

    private static final String PATTERN_FORMAT = "HH:mm:ss dd.MM.yyyy.";
    private final ISigningSessionRepository signingSessionRepository;
    private IStorageService storageService;
    private IEmailService emailService;
    private ISmsService smsService;
    private GeoIPLocationService locationService;
    private SigningService signingService;
    private CertificateGenerationService certificateGenerationService;

    public static String HashWithBouncyCastle(final String originalString) throws NoSuchAlgorithmException {
        final MessageDigest digest = MessageDigest.getInstance("SHA-256");
        final byte[] hash = digest.digest(originalString.getBytes(StandardCharsets.UTF_8));
        final String sha256hex = new String(Hex.encode(hash));
        return sha256hex;
    }


    @Override
    public SigningSession findById(UUID id) {
        Optional<SigningSession> signingSessionOptional = signingSessionRepository.findById(id);
        if (!signingSessionOptional.isPresent()) {
            throw new EntityNotFoundException(SigningSession.class, "id", id.toString());
        }
        return signingSessionOptional.get();
    }

    @Override
    public SigningSession save(SigningSession signingSession) {
        return signingSessionRepository.save(signingSession);
    }

    @Override
    public List<SigningSession> findByUserId(UUID userId) {
        List<SigningSession> signingSessions = signingSessionRepository.findByUserId(userId);
        if (signingSessions.isEmpty()) {
            throw new EntityNotFoundException(SigningSession.class, "userId", userId.toString());
        }
        return signingSessions;
    }

    @Override
    public SigningSession initiateSigningSession(MultipartFile file, Map<String, Object> principalClaims)
            throws IOException {

        Path filePath = storageService.store(file);
        String fileName = filePath.getFileName().toString();


        PdfDocument pdfDocument = new PdfDocument(new PdfReader(filePath.toString()));
        SignatureUtil signUtil = new SignatureUtil(pdfDocument);
        List<String> names = signUtil.getSignatureNames();
        if (!names.isEmpty()) {
            throw new DocumentAlreadySignedException("Document " + fileName + " is already signed");
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

        return save(signingSession);
    }

    @Override
    public SigningSession cancelSigningSession(SigningSession signingSession) {
        if (signingSession.getStatus() != Status.PENDING && signingSession.getStatus() != Status.IN_PROGRESS) {
            throw new InvalidStatusException(
                    "Only signing sessions with status 'Pending' or 'In Progress' can be canceled.");
        }
        else {
            signingSession.setStatus(Status.CANCELED);
            return save(signingSession);
        }

    }

    @Override
    public SigningSession approveSigningSession(SigningSession signingSession, ApproveSigningSessionRequest request,
                                                Map<String, Object> principalClaims)
            throws Exception {

        Boolean consent = request.getConsent();
        Long certRequestedAt = request.getCertRequestedAt();

        if (signingSession.getStatus() != Status.PENDING) {
            throw new InvalidStatusException(
                    "Only signing sessions with status 'Pending' can be approved");
        }

        if (!consent) {
            throw new ConsentRequiredException("Consent is required");
        }

        signingSession.setConsent(true);
        String keystorePassword =
                certificateGenerationService.generateUserCertificate(principalClaims, signingSession, certRequestedAt);

        signingSession.setStatus(Status.IN_PROGRESS);

        // TODO crl istice nakon 7 dana, moras pred odbranu novi da generises

//        smsService.sendSigningSms(principalClaims, keystorePassword);
        emailService.sendSigningEmail(principalClaims, keystorePassword);

        return save(signingSession);
    }

    @Override
    @Transactional(noRollbackFor = SigningSessionSuspendedException.class)
    public SigningSession resendCode(SigningSession signingSession, Map<String, Object> principalClaims,
                                     Long certRequestedAt)
            throws Exception {


        if (signingSession.getStatus() != Status.IN_PROGRESS) {
            throw new InvalidStatusException(
                    "Code can be resent only for signing sessions with status 'In Progress'");
        }

        if (signingSession.getSuspendedUntil() != null) {
            long currentTimestamp = Instant.now().getEpochSecond();

            if (currentTimestamp > signingSession.getSuspendedUntil()) {
                return generateAndSendCode(signingSession, 1, principalClaims, certRequestedAt);
            }

            Instant instant = Instant.ofEpochSecond(signingSession.getSuspendedUntil());
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern(PATTERN_FORMAT)
                    .withZone(ZoneId.systemDefault());
            throw new SigningSessionSuspendedException(
                    "Signing session is suspended until " + formatter.format(instant) +
                            " due to exceeding the number of allowed attempts to resend code");
        }

        if (signingSession.getResendAttempts() == 3) {
            long currentTimestamp = Instant.now().getEpochSecond();
            long plus30Minutes = currentTimestamp + TimeUnit.MINUTES.toSeconds(30);
            signingSession.setSuspendedUntil(plus30Minutes);
            save(signingSession);
            Instant instant = Instant.ofEpochSecond(plus30Minutes);
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern(PATTERN_FORMAT)
                    .withZone(ZoneId.systemDefault());
            throw new SigningSessionSuspendedException(
                    "Signing session is suspended until " + formatter.format(instant) +
                            " due to exceeding the number of allowed attempts to resend code");
        }

        return generateAndSendCode(signingSession, signingSession.getResendAttempts() + 1, principalClaims,
                certRequestedAt);

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

    private SigningSession generateAndSendCode(SigningSession signingSession, int resendAttempts,
                                               Map<String, Object> principalClaims, Long certRequestedAt)
            throws Exception {

        // delete previous certificate
        storageService.deleteKeystore(signingSession.getCertificate().getSerialNumber() + ".pfx");

        String keystorePassword =
                certificateGenerationService.generateUserCertificate(principalClaims, signingSession, certRequestedAt);


        signingSession.setResendAttempts(resendAttempts);
        signingSession.setSuspendedUntil(null);

//        smsService.sendSigningSms(principalClaims, keystorePassword);
        emailService.sendSigningEmail(principalClaims, keystorePassword);
        return save(signingSession);
    }

    @Override
    @Transactional(noRollbackFor = {InvalidStatusException.class, InvalidKeystorePassException.class})
    public SigningSession sign(SigningSession signingSession, String keystorePassword, String clientIp,
                               Map<String, Object> principalClaims)
            throws Exception {

        /* TODO Proveri user id iz sesije sa SUB claim-om iz tokena
         * Kako se ovo gore moze zloupotrebiti:
         * User A zapocne sesiju i dodje do potpisivanja
         * User B se autentikuje i (nekako) ukrade podatke o sesiji usera A ali ne ukrade tokne
         * User B proba sa svojim tokenom da potpise sesiju korisnika A
         * Sistem ga zbog provere u gornjem t-o-d-o odbija
         */
        if (!signingSession.getUserId().toString().equals(principalClaims.get("sub"))) {
            // TODO Napravi novi Exception koji odgovara ovoj proveri
            throw new InvalidStatusException(
                    "Provided session does not belong to current user (caller)");
        }
        if (signingSession.getStatus() == Status.REJECTED) {
            throw new InvalidStatusException(
                    "Your signing session has been rejected due to entering invalid code 3 times");
        }

        if (signingSession.getStatus() != Status.IN_PROGRESS) {
            throw new InvalidStatusException(
                    "Document can be signed only for signing sessions with status 'In Progress'");
        }

        if (signingSession.getSuspendedUntil() != null) {
            Instant instant = Instant.ofEpochSecond(signingSession.getSuspendedUntil());
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern(PATTERN_FORMAT)
                    .withZone(ZoneId.systemDefault());
            throw new SigningSessionSuspendedException(
                    "Signing session is suspended until " + formatter.format(instant) +
                            " due to exceeding the number of allowed attempts to resend code");
        }

        if (signingSession.getSignAttempts() == 3) {
            rejectSigning(signingSession);
            throw new InvalidStatusException(
                    "Your signing session has been rejected due to entering invalid code 3 times");
        }
        else {
            boolean keystorePasswordVerified =
                    certificateGenerationService.verifyKeystorePassword(signingSession, keystorePassword);
            if (!keystorePasswordVerified) {
                addSigningAttempt(signingSession);
                throw new InvalidKeystorePassException("Invalid code");
            }
            else {
                Path signedFilePath = signingService.sign(signingSession, clientIp, principalClaims, keystorePassword);
                signingSession.setStatus(Status.SIGNED);
                signingSession.getDocument().setSignedFilePath(signedFilePath.toAbsolutePath().toString());
                signingSession.getDocument().setSignedFileName(signedFilePath.getFileName().toString());

                return save(signingSession);
            }
        }
    }


    @Override
    public Resource getUnsignedDocument(SigningSession signingSession) {
        if (signingSession.getStatus() != Status.SIGNED) {
            return storageService.loadAsResource(signingSession.getDocument().getFileName(), false);
        }
        throw new InvalidStatusException(
                "Unsigned document can be downloaded only for signing sessions with status other than 'Signed'");
    }

    @Override
    public Resource getSignedDocument(SigningSession signingSession) {
        if (signingSession.getStatus() != Status.SIGNED) {
            throw new InvalidStatusException(
                    "Signed document can be downloaded only for signing sessions with status 'Signed'");
        }
        return storageService.loadAsResource(signingSession.getDocument().getSignedFileName(),
                true);
    }
}
