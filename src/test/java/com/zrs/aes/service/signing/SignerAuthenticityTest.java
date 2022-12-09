package com.zrs.aes.service.signing;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.signatures.SignatureUtil;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.zrs.aes.persistence.model.Document;
import com.zrs.aes.persistence.model.SigningSession;
import com.zrs.aes.persistence.model.Status;
import com.zrs.aes.persistence.repository.ISigningSessionRepository;
import com.zrs.aes.service.email.IEmailService;
import com.zrs.aes.service.location.GeoIP;
import com.zrs.aes.service.location.GeoIPLocationService;
import com.zrs.aes.service.signingSession.SigningSessionServiceImpl;
import com.zrs.aes.service.sms.ISmsService;
import com.zrs.aes.service.storage.IStorageService;
import com.zrs.aes.service.totp.TotpService;
import com.zrs.aes.web.customexceptions.InvalidStatusException;
import dev.samstevens.totp.time.SystemTimeProvider;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import javax.mail.MessagingException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(initializers = ConfigDataApplicationContextInitializer.class)
@EnableConfigurationProperties(value = SigningProperties.class)
@ActiveProfiles("local")
public class SignerAuthenticityTest {
    private final String givenName = "Katarina";
    private final String familyName = "Vucic";
    private final String signatureFieldName = "Advanced Electronic Signature";
    private final String certSubjectName =
            "CN=www.aes.com,OU=Zastita racunarskih sistema,O=Fakultet organizacionih nauka,L=Belgrade,ST=Serbia,C=RS";
    private final Path fileToBeSignedPath = Paths.get("src/main/resources/static/uploadedDocuments/a.pdf");
    private final String reason = """
            On behalf of Katarina Vucic, kattylicious98@gmail.com
            Using OTP 123456 and timestamp 1668872875
            Hash value of document: c92376579219dfdf9241c7eb35298388014906667757348a91540f1391d2b757""";
    // TODO Sredi hash i odakle se cita
    private final String contact = "kattylicious98@gmail.com";
    private final String clientIp = "192.168.0.55";

    SigningProperties signingProperties;
    @Mock
    IStorageService storageService;
    @Mock
    GeoIPLocationService locationService;
    @Mock
    ISigningSessionRepository signingSessionRepository;
    @Mock
    IEmailService emailService;
    @Mock
    ISmsService smsService;
    TotpService totpService = new TotpService();
    SigningService signingService;
    SignatureUtil util;
    PdfDocument pdfDocument;
    SigningSession signingSession;
    SigningSessionServiceImpl signingSessionService;
    Map<String, Object> principalClaims;

    @BeforeEach
    void setUp() throws GeneralSecurityException, IOException, GeoIp2Exception, MessagingException {
        MockitoAnnotations.openMocks(this);

        // ARRANGE

        // Arrange globals
        signingProperties = new SigningProperties();
        signingProperties.setKeyPass("katarina");
        signingProperties.setStorePass("katarina");
        signingService = new SigningService(signingProperties, storageService, locationService);
        principalClaims = new HashMap();
        principalClaims.put("email", contact);
        principalClaims.put("given_name", givenName);
        principalClaims.put("family_name", familyName);
        principalClaims.put("sub", "d59d13ba-da98-47a5-b245-cd82698adfdd");

        // Arrange Initiate session deps
        File initialFile = new File("src/main/resources/static/uploadedDocuments/a.pdf");
        InputStream targetStream = new FileInputStream(initialFile);
        MockMultipartFile file = new MockMultipartFile("a.pdf", targetStream);
        when(storageService.store(any())).thenReturn(fileToBeSignedPath);

        // Arrange Approve signing deps
        signingSessionService = new SigningSessionServiceImpl(signingSessionRepository,
                storageService, emailService, smsService, totpService, locationService, signingService);

        when(signingSessionService.save(any(SigningSession.class))).thenAnswer(i -> i.getArguments()[0]);

        // Arrange Signing deps
        when(locationService.getLocation(anyString()))
                .thenReturn(new GeoIP(clientIp, "Belgrade", "Serbia", "44", "22"));
        when(storageService.load(anyString()))
                .thenReturn(fileToBeSignedPath);

        // ACT

        // Initiate session
        signingSession = signingSessionService.initiateSigningSession(file, principalClaims);

        // Approve signing
        signingSession = signingSessionService.approveSigningSession(signingSession, true, principalClaims);
    }

    @AfterEach
    void tearDown() {
        // TODO Check this
        signingService = null;
        signingSessionService = null;
        signingSession = null;
        util = null;
    }

    @Test
    @DisplayName("Reject different principal than one initiated the session")
    void rejectDifferentPrincipal() throws IOException, GeneralSecurityException, GeoIp2Exception {
        Map<String, Object> principalClaimsForged = new HashMap();
        principalClaims.put("email", "something@el.se");
        principalClaims.put("given_name", "John");
        principalClaims.put("family_name", "Doe");
        principalClaims.put("sub", "a59d13ba-da98-47a5-b245-cd82698adfda");
        // Sign document
        Exception exception = assertThrows(InvalidStatusException.class, () -> {
            signingSessionService.sign(signingSession, signingSession.getOneTimePassword().getOtp(), clientIp, principalClaimsForged);
        });
        String expectedMessage = "Provided session does not belong to current user (caller)";
        String actualMessage = exception.getMessage();

        assertEquals(actualMessage, expectedMessage, expectedMessage);
    }

    @Test
    @DisplayName("Accept only the same principal as one initiated the session")
    void acceptValidPrincipal() throws IOException, GeneralSecurityException, GeoIp2Exception {
        // Sign document
        assertDoesNotThrow(() ->
                signingSessionService.sign(signingSession, signingSession.getOneTimePassword().getOtp(),
                        clientIp, principalClaims),
                "Same principal as one initiated the session is accepted");
    }
}
