package com.zrs.aes.service.signingSession;

import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.zrs.aes.persistence.model.OTP;
import com.zrs.aes.persistence.model.SigningSession;
import com.zrs.aes.persistence.repository.ISigningSessionRepository;
import com.zrs.aes.service.email.IEmailService;
import com.zrs.aes.service.location.GeoIP;
import com.zrs.aes.service.location.GeoIPLocationService;
import com.zrs.aes.service.location.HttpUtils;
import com.zrs.aes.service.signing.SigningService;
import com.zrs.aes.service.storage.IStorageService;
import com.zrs.aes.service.totp.TotpService;
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
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@Transactional
@Slf4j
@AllArgsConstructor
public class SigningSessionServiceImpl implements ISigningSessionService {

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
    public SigningSession initiateSigningSession(MultipartFile file, Jwt principal) throws MessagingException {
        Path filePath = storageService.store(file);
        String fileName = filePath.getFileName().toString();

        String secret = UUID.randomUUID().toString();
        OTP otp = totpService.getCodeObject(secret);

        DateTimeFormatter dtf = DateTimeFormatter.ofPattern("dd/MM/yyyy");
        SigningSession signingSession = SigningSession.builder()
                .id(secret)
                .userId(principal.getClaimAsString("sub"))
                .addedOn(dtf.format(LocalDateTime.now()))
                .filePath(filePath.toAbsolutePath().toString())
                .fileName(fileName)
                .otp(otp.getOtp())
                .timestamp(otp.getTimestamp())
                .build();

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

        signingSession.setSigned(true);
        signingSession.setSignedFilePath(signedFilePath.toAbsolutePath().toString());
        signingSession.setSignedFileName(signedFilePath.getFileName().toString());
        save(signingSession);

        return principal.getClaimAsString("given_name")
                + ", document "
                + fileToBeSignedPath.getFileName().toString()
                + " has been successfully signed on your behalf!";
    }
}
