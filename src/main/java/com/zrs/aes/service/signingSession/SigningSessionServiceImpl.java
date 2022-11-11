package com.zrs.aes.service.signingSession;

import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.zrs.aes.persistence.model.OTP;
import com.zrs.aes.persistence.model.SigningSession;
import com.zrs.aes.persistence.model.Status;
import com.zrs.aes.persistence.repository.ISigningSessionRepository;
import com.zrs.aes.service.email.IEmailService;
import com.zrs.aes.service.location.GeoIP;
import com.zrs.aes.service.location.GeoIPLocationService;
import com.zrs.aes.service.location.HttpUtils;
import com.zrs.aes.service.signing.SigningService;
import com.zrs.aes.service.storage.IStorageService;
import com.zrs.aes.service.totp.TotpService;
import com.zrs.aes.web.exception.SigningSessionSuspendedException;
import dev.samstevens.totp.time.SystemTimeProvider;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;
import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileInputStream;
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
    private TotpService totpService;
    private GeoIPLocationService locationService;
    private SigningService signingService;

    public static String HashWithBouncyCastle(final String originalString) throws NoSuchAlgorithmException {
        final MessageDigest digest = MessageDigest.getInstance("SHA-256");
        final byte[] hash = digest.digest(originalString.getBytes(StandardCharsets.UTF_8));
        final String sha256hex = new String(Hex.encode(hash));
        return sha256hex;
    }

    private static String getFileChecksum(MessageDigest digest, File file) throws IOException {
        //Get file input stream for reading the file content
        FileInputStream fis = new FileInputStream(file);

        //Create byte array to read data in chunks
        byte[] byteArray = new byte[1024];
        int bytesCount = 0;

        //Read file data and update in message digest
        while ((bytesCount = fis.read(byteArray)) != -1) {
            digest.update(byteArray, 0, bytesCount);
        }
        ;

        //close the stream; We don't need it now.
        fis.close();

        //Get the hash's bytes
        byte[] bytes = digest.digest();

        //This bytes[] has bytes in decimal format;
        //Convert it to hexadecimal format
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
        }

        //return complete hash
        return sb.toString();
    }

    @Override
    public Optional<SigningSession> findById(String id) {
        return signingSessionRepository.findById(id);
    }

    @Override
    public SigningSession findByFilePath(String filePath) {
        return signingSessionRepository.findByFilePath(filePath);
    }

    @Override
    public SigningSession save(SigningSession signingSession) {
        return signingSessionRepository.save(signingSession);
    }

    @Override
    public List<SigningSession> findByUserId(String userId) {
        return signingSessionRepository.findByUserId(userId);
    }

    @Override
    public SigningSession initiateSigningSession(MultipartFile file, Jwt principal)
            throws MessagingException {
        Path filePath = storageService.store(file);
        String fileName = filePath.getFileName().toString();

        SigningSession signingSession = SigningSession.builder()
                .id(UUID.randomUUID().toString())
                .userId(principal.getClaimAsString("sub"))
                .addedOn(new SystemTimeProvider().getTime())
                .filePath(filePath.toAbsolutePath().toString())
                .fileName(fileName)
                .status(Status.PENDING)
                .build();
        return save(signingSession);
    }

    @Override
    public SigningSession cancelSigningSession(SigningSession signingSession, Jwt principal) {
        signingSession.setStatus(Status.CANCELED);
        return save(signingSession);
    }

    @Override
    public SigningSession startSigningSession(SigningSession signingSession, boolean consent, Jwt principal)
            throws MessagingException {

        String secret = UUID.randomUUID().toString();
        OTP otp = totpService.getCodeObject(secret);

        signingSession.setConsent(consent);
        signingSession.setOtp(otp.getOtp());
        signingSession.setSecret(secret);
        signingSession.setTimestamp(otp.getTimestamp());
        signingSession.setStatus(Status.IN_PROGRESS);

        emailService.sendSigningEmail(principal, signingSession.getOtp());

        return save(signingSession);
    }

    @Override
    @Transactional(noRollbackFor = SigningSessionSuspendedException.class)
    public SigningSession resendOtp(SigningSession signingSession, Jwt principal)
            throws MessagingException {

        if (signingSession.getSuspendedUntil() != null) {
            long currentTimestamp = new SystemTimeProvider().getTime();
            if (currentTimestamp > signingSession.getSuspendedUntil()) {
                return generateAndSendOtp(signingSession, 1, principal);
            }
            else {
                Instant instant = Instant.ofEpochSecond(signingSession.getSuspendedUntil());
                DateTimeFormatter formatter = DateTimeFormatter.ofPattern(PATTERN_FORMAT)
                        .withZone(ZoneId.systemDefault());
                throw new SigningSessionSuspendedException(
                        "Signing session is suspended until " + formatter.format(instant) +
                                " due to exceeding the number of allowed attempts to resend OTP.");
            }
        }
        else {
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
                                " due to exceeding the number of allowed attempts to resend OTP.");
            }
            else {
                return generateAndSendOtp(signingSession, signingSession.getOtpAttempts() + 1, principal);
            }
        }
    }

    @Override
    public SigningSession addSigningAttempt(SigningSession signingSession, Jwt principal) {
        signingSession.setSignAttempts(signingSession.getSignAttempts() + 1);
        return save(signingSession);
    }

    @Override
    public SigningSession rejectSigning(SigningSession signingSession, Jwt principal) {
        signingSession.setStatus(Status.REJECTED);
        return save(signingSession);
    }

    private SigningSession generateAndSendOtp(SigningSession signingSession, int otpAttempts,
                                              Jwt principal)
            throws MessagingException {
        String secret = UUID.randomUUID().toString();
        OTP otp = totpService.getCodeObject(secret);

        signingSession.setOtp(otp.getOtp());
        signingSession.setSecret(secret);
        signingSession.setTimestamp(otp.getTimestamp());

        signingSession.setOtpAttempts(otpAttempts);
        signingSession.setSuspendedUntil(null);

        emailService.sendSigningEmail(principal, signingSession.getOtp());
        return save(signingSession);
    }

    @Override
    public String sign(SigningSession signingSession, String otp, HttpServletRequest request, Jwt principal)
            throws IOException, GeoIp2Exception, GeneralSecurityException {

        Path fileToBeSignedPath = storageService.load(signingSession.getFileName());

        GeoIP geoIP;
        String clientIp = HttpUtils.getRequestIPAddress(request);
        if (clientIp.equals("0:0:0:0:0:0:0:1") || clientIp.equals("127.0.0.1")) {
            geoIP = locationService.getLocation("87.116.160.153");
        }
        else {
            geoIP = locationService.getLocation(clientIp);
        }
        String location = geoIP.getCity() + ", " + geoIP.getCountry();

        File fileToBeSigned = new File(signingSession.getFilePath());
//        HashCode hash = Files.hash(fileToBeSigned, Hashing.md5());
        MessageDigest shaDigest = MessageDigest.getInstance("SHA-256");
        String shaChecksum = getFileChecksum(shaDigest, fileToBeSigned);


        String reason = "On behalf of " + principal.getClaimAsString("given_name") + " " +
                principal.getClaimAsString("family_name") + ", " + principal.getClaimAsString("email") + "\n"
                + "Using OTP " + signingSession.getOtp() + " and timestamp " + signingSession.getTimestamp() + "\n"
                +
                "Hash value of document: " + shaChecksum;

        Path signedFilePath =
                signingService.sign(fileToBeSignedPath, reason, location, principal.getClaimAsString("email"));
        File signedFile = signedFilePath.toFile();

        signingSession.setStatus(Status.SIGNED);
        signingSession.setSignedFilePath(signedFilePath.toAbsolutePath().toString());
        signingSession.setSignedFileName(signedFilePath.getFileName().toString());
        save(signingSession);

        return principal.getClaimAsString("given_name")
                + ", document "
                + fileToBeSignedPath.getFileName().toString()
                + " has been successfully signed on your behalf!";
    }
}
