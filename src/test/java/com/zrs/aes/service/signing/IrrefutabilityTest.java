//package com.zrs.aes.service.signing;
//
//import com.itextpdf.kernel.pdf.PdfDocument;
//import com.itextpdf.kernel.pdf.PdfReader;
//import com.itextpdf.signatures.PdfSignature;
//import com.itextpdf.signatures.SignatureUtil;
//import com.maxmind.geoip2.exception.GeoIp2Exception;
//import com.zrs.aes.persistence.model.Document;
//import com.zrs.aes.persistence.model.OneTimePassword;
//import com.zrs.aes.persistence.model.SigningSession;
//import com.zrs.aes.persistence.model.Status;
//import com.zrs.aes.persistence.repository.ISigningSessionRepository;
//import com.zrs.aes.service.email.EmailServiceImpl;
//import com.zrs.aes.service.email.IEmailService;
//import com.zrs.aes.service.location.GeoIP;
//import com.zrs.aes.service.location.GeoIPLocationService;
//import com.zrs.aes.service.signingSession.SigningSessionServiceImpl;
//import com.zrs.aes.service.sms.ISmsService;
//import com.zrs.aes.service.storage.IStorageService;
//import com.zrs.aes.service.totp.TotpService;
//import dev.samstevens.totp.time.SystemTimeProvider;
//import org.junit.jupiter.api.AfterEach;
//import org.junit.jupiter.api.BeforeEach;
//import org.junit.jupiter.api.DisplayName;
//import org.junit.jupiter.api.Test;
//import org.junit.jupiter.api.extension.ExtendWith;
//import org.mockito.Mock;
//import org.mockito.MockitoAnnotations;
//import org.springframework.boot.context.properties.EnableConfigurationProperties;
//import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
//import org.springframework.mail.javamail.JavaMailSender;
//import org.springframework.test.context.ActiveProfiles;
//import org.springframework.test.context.ContextConfiguration;
//import org.springframework.test.context.junit.jupiter.SpringExtension;
//import org.thymeleaf.ITemplateEngine;
//
//import javax.mail.MessagingException;
//import javax.mail.internet.MimeMessage;
//import java.io.IOException;
//import java.nio.file.Path;
//import java.nio.file.Paths;
//import java.security.GeneralSecurityException;
//import java.util.HashMap;
//import java.util.Map;
//import java.util.UUID;
//
//import static org.junit.jupiter.api.Assertions.*;
//import static org.mockito.Mockito.*;
//
//@ExtendWith(SpringExtension.class)
//@ContextConfiguration(initializers = ConfigDataApplicationContextInitializer.class)
//@EnableConfigurationProperties(value = SigningProperties.class)
//@ActiveProfiles("local")
//public class IrrefutabilityTest {
//    private final String givenName = "Katarina";
//    private final String familyName = "Vucic";
//    private final String signatureFieldName = "Advanced Electronic Signature";
//    private final String certSubjectName =
//            "CN=www.aes.com,OU=Zastita racunarskih sistema,O=Fakultet organizacionih nauka,L=Belgrade,ST=Serbia,C=RS";
//    private final Path fileToBeSignedPath = Paths.get("src/main/resources/static/uploadedDocuments/a.pdf");
//    private final String reason = """
//            On behalf of Katarina Vucic, kattylicious98@gmail.com
//            Using OTP 123456 and timestamp 1668872875
//            Hash value of document: c92376579219dfdf9241c7eb35298388014906667757348a91540f1391d2b757""";
//    // TODO Sredi hash i odakle se cita
//    private final String contact = "kattylicious98@gmail.com";
//    private final String clientIp = "192.168.0.55";
//
//    SigningProperties signingProperties;
//    @Mock
//    IStorageService storageService;
//    @Mock
//    GeoIPLocationService locationService;
//    @Mock
//    ISigningSessionRepository signingSessionRepository;
//    @Mock
//    IEmailService emailService;
//    @Mock
//    ISmsService smsService;
//    TotpService totpService = new TotpService();
//    SigningService signingService;
//    SignatureUtil util;
//    PdfDocument pdfDocument;
//    SigningSession signingSession;
//
//    @BeforeEach
//    void setUp() throws GeneralSecurityException, IOException, GeoIp2Exception, MessagingException {
//        MockitoAnnotations.openMocks(this);
//
//        // ARRANGE
//
//        // Arrange globals
//        signingProperties = new SigningProperties();
//        signingProperties.setKeyPass("katarina");
//        signingProperties.setStorePass("katarina");
//        signingService = new SigningService(signingProperties, storageService, locationService);
//        Map<String, Object> principalClaims = new HashMap();
//        principalClaims.put("email", contact);
//        principalClaims.put("given_name", givenName);
//        principalClaims.put("family_name", familyName);
//        principalClaims.put("sub", "d59d13ba-da98-47a5-b245-cd82698adfdd");
//
//        signingSession = SigningSession.builder()
//                .userId(UUID.fromString((String) principalClaims.get("sub")))
//                .status(Status.PENDING)
//                .build();
//
//        Document document = Document.builder()
//                .signingSession(signingSession)
//                .filePath(fileToBeSignedPath.toAbsolutePath().toString())
//                .fileName(fileToBeSignedPath.getFileName().toString())
//                .addedOn(new SystemTimeProvider().getTime())
//                .build();
//
//        signingSession.setDocument(document);
//
//        // Arrange Approve signing deps
//        SigningSessionServiceImpl signingSessionService = new SigningSessionServiceImpl(signingSessionRepository,
//                storageService, emailService, smsService, totpService, locationService, signingService);
//
//        when(signingSessionService.save(any(SigningSession.class))).thenAnswer(i -> i.getArguments()[0]);
//
//        // Arrange Signing deps
//        when(locationService.getLocation(anyString()))
//                .thenReturn(new GeoIP(clientIp, "Belgrade", "Serbia", "44", "22"));
//        when(storageService.load(anyString()))
//                .thenReturn(fileToBeSignedPath);
//
//        // ACT
//
//        // Approve signing
//        signingSession = signingSessionService.approveSigningSession(signingSession, true, principalClaims);
//
//        // Sign document
//        Path outPdfPath = signingService.sign(signingSession, clientIp, principalClaims);
//        // extract signature details
//        pdfDocument = new PdfDocument(new PdfReader(outPdfPath.toString()));
//        util = new SignatureUtil(pdfDocument);
//    }
//
//    @AfterEach
//    void tearDown() {
//        // TODO Check this
//        signingService = null;
//        util = null;
//
//        // close file
//        pdfDocument.close();
//        pdfDocument = null;
//    }
//
//    @Test
//    @DisplayName("Signing session fields updated during approval")
//    void sessionFieldsUpdated() {
//        assertNotNull(signingSession.getOneTimePassword(), "OneTimePassword created");
//        assertTrue(signingSession.getConsent(), "Consent for signing is given");
//        assertEquals(Status.IN_PROGRESS, signingSession.getStatus(), "Status is changed to IN PROGRESS");
//    }
//
//    @Test
//    @DisplayName("Signed and approved document fields correspond")
//    void testSignedDocumentFieldsAndApproved() {
//        // test fields
//        PdfSignature sig = util.getSignature(signatureFieldName);
//        assertNotNull(sig.getReason(), "Reason is not null");
//        assertTrue(sig.getReason().contains("On behalf of Katarina Vucic"), "Reason contains valid signer name");
//        OneTimePassword otpCode = totpService
//                .getCodeObject(signingSession.getOneTimePassword().getTimestamp(),
//                        signingSession.getOneTimePassword().getSecret());
//        assertTrue(sig.getReason().contains("Using OTP " + otpCode.getOtp()), "Reason contains valid OTP code");
//    }
//}
