package com.zrs.aes.service.signingSession;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.signatures.SignatureUtil;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.zrs.aes.persistence.model.Document;
import com.zrs.aes.persistence.model.OneTimePassword;
import com.zrs.aes.persistence.model.SigningSession;
import com.zrs.aes.persistence.model.Status;
import com.zrs.aes.persistence.repository.ISigningSessionRepository;
import com.zrs.aes.service.email.IEmailService;
import com.zrs.aes.service.location.GeoIPLocationService;
import com.zrs.aes.service.signing.SigningService;
import com.zrs.aes.service.sms.ISmsService;
import com.zrs.aes.service.storage.IStorageService;
import com.zrs.aes.service.totp.TotpService;
import com.zrs.aes.web.customexceptions.*;
import dev.samstevens.totp.time.SystemTimeProvider;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
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
    private TotpService totpService;
    private GeoIPLocationService locationService;
    private SigningService signingService;

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
                .addedOn(new SystemTimeProvider().getTime())
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
    public SigningSession approveSigningSession(SigningSession signingSession, Boolean consent,
                                                Map<String, Object> principalClaims)
            throws MessagingException {

        if (signingSession.getStatus() != Status.PENDING) {
            throw new InvalidStatusException(
                    "Only signing sessions with status 'Pending' can be approved");
        }

        if (!consent) {
            throw new ConsentRequiredException("Consent is required");
        }

        signingSession.setConsent(true);
        OneTimePassword oneTimePassword = totpService.getCodeObject();
        oneTimePassword.setSigningSession(signingSession);

        signingSession.setOneTimePassword(oneTimePassword);
        signingSession.setStatus(Status.IN_PROGRESS);
        smsService.sendSigningSms(principalClaims, oneTimePassword.getOtp());
        emailService.sendSigningEmail(principalClaims, oneTimePassword.getOtp());

        return save(signingSession);
    }

    @Override
    @Transactional(noRollbackFor = SigningSessionSuspendedException.class)
    public SigningSession resendOtp(SigningSession signingSession, Map<String, Object> principalClaims)
            throws MessagingException {


        if (signingSession.getStatus() != Status.IN_PROGRESS) {
            throw new InvalidStatusException(
                    "OTP can be resent only for signing sessions with status 'In Progress'");
        }

        if (signingSession.getSuspendedUntil() != null) {
            long currentTimestamp = new SystemTimeProvider().getTime();

            if (currentTimestamp > signingSession.getSuspendedUntil()) {
                return generateAndSendOtp(signingSession, 1, principalClaims);
            }

            Instant instant = Instant.ofEpochSecond(signingSession.getSuspendedUntil());
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern(PATTERN_FORMAT)
                    .withZone(ZoneId.systemDefault());
            throw new SigningSessionSuspendedException(
                    "Signing session is suspended until " + formatter.format(instant) +
                            " due to exceeding the number of allowed attempts to resend OTP");
        }

        if (signingSession.getOtpAttempts() == 3) {
            long currentTimestamp = new SystemTimeProvider().getTime();
            long plus30Minutes = currentTimestamp + TimeUnit.MINUTES.toSeconds(30);
            signingSession.setSuspendedUntil(plus30Minutes);
            save(signingSession);
            Instant instant = Instant.ofEpochSecond(plus30Minutes);
            DateTimeFormatter formatter = DateTimeFormatter.ofPattern(PATTERN_FORMAT)
                    .withZone(ZoneId.systemDefault());
            throw new SigningSessionSuspendedException(
                    "Signing session is suspended until " + formatter.format(instant) +
                            " due to exceeding the number of allowed attempts to resend OTP");
        }

        return generateAndSendOtp(signingSession, signingSession.getOtpAttempts() + 1, principalClaims);

    }

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

    private SigningSession generateAndSendOtp(SigningSession signingSession, int otpAttempts,
                                              Map<String, Object> principalClaims)
            throws MessagingException {

        OneTimePassword newOneTimePassword = totpService.getCodeObject();

        signingSession.getOneTimePassword().setOtp(newOneTimePassword.getOtp());
        signingSession.getOneTimePassword().setTimestamp(newOneTimePassword.getTimestamp());
        signingSession.getOneTimePassword().setSecret(newOneTimePassword.getSecret());

        signingSession.setOtpAttempts(otpAttempts);
        signingSession.setSuspendedUntil(null);

        smsService.sendSigningSms(principalClaims, signingSession.getOneTimePassword().getOtp());
        emailService.sendSigningEmail(principalClaims, signingSession.getOneTimePassword().getOtp());
        return save(signingSession);
    }

    @Override
    @Transactional(noRollbackFor = {InvalidStatusException.class, InvalidOTPException.class})
    public SigningSession sign(SigningSession signingSession, String otp, String clientIp,
                               Map<String, Object> principalClaims)
            throws IOException, GeneralSecurityException, GeoIp2Exception {

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
                    "Your signing session has been rejected due to entering invalid or expired OTP 3 times");
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
                            " due to exceeding the number of allowed attempts to resend OTP");
        }

        if (signingSession.getSignAttempts() == 3) {
            rejectSigning(signingSession);
            throw new InvalidStatusException(
                    "Your signing session has been rejected due to entering invalid or expired OTP 3 times");
        }
        else {
            boolean codeVerified =
                    totpService.verifyCode(signingSession.getOneTimePassword().getSecret(), otp);
            if (!codeVerified) {
                addSigningAttempt(signingSession);
                throw new InvalidOTPException("Invalid or expired OTP");
            }
            else {
                Path signedFilePath = signingService.sign(signingSession, clientIp, principalClaims);

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
