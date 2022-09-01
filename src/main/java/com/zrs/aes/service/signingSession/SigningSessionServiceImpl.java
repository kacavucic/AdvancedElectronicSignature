package com.zrs.aes.service.signingSession;

import com.google.common.hash.HashCode;
import com.google.common.hash.Hashing;
import com.google.common.io.Files;
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
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import javax.mail.MessagingException;
import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
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
    public SigningSession initiateSigningSession(MultipartFile file, Jwt principal) throws MessagingException {
        Path filePath = storageService.store(file);
        String fileName = filePath.getFileName().toString();

        String secret = UUID.randomUUID().toString();
        OTP otp = totpService.getCodeObject(secret);

        SigningSession signingSession = SigningSession.builder()
                .id(secret)
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
        HashCode hash = Files.hash(fileToBeSigned, Hashing.md5());

        String reason = "On behalf of " + principal.getClaimAsString("given_name") + " " +
                principal.getClaimAsString("family_name") + ", " + principal.getClaimAsString("email") + "\n"
                + "Using OTP " + signingSession.getOtp() + " and timestamp " + signingSession.getTimestamp() + "\n"
                +
                "Hash value of document: " + hash;

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
