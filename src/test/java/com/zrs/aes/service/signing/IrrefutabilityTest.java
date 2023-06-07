package com.zrs.aes.service.signing;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.signatures.PdfSignature;
import com.itextpdf.signatures.SignatureUtil;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.zrs.aes.mapper.SigningSessionMapper;
import com.zrs.aes.persistence.model.Certificate;
import com.zrs.aes.persistence.model.Document;
import com.zrs.aes.persistence.model.SigningSession;
import com.zrs.aes.persistence.model.Status;
import com.zrs.aes.persistence.repository.SigningSessionRepository;
import com.zrs.aes.service.certificate.CertificateGenerationService;
import com.zrs.aes.service.certificate.KeystoreLoader;
import com.zrs.aes.service.email.EmailService;
import com.zrs.aes.service.location.GeoIP;
import com.zrs.aes.service.location.GeoIPLocationService;
import com.zrs.aes.service.location.HttpUtils;
import com.zrs.aes.service.signingsession.SigningSessionServiceImpl;
import com.zrs.aes.service.sms.SmsService;
import com.zrs.aes.service.storage.StorageProperties;
import com.zrs.aes.service.storage.StorageService;
import com.zrs.aes.service.storage.StorageServiceImpl;
import com.zrs.aes.util.AuthUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import javax.mail.MessagingException;
import javax.servlet.http.HttpServletRequest;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@SpringBootTest
@TestPropertySource(locations = "classpath:application.yml")
@ExtendWith(SpringExtension.class)
@ContextConfiguration(initializers = ConfigDataApplicationContextInitializer.class)
@ActiveProfiles("local")
class IrrefutabilityTest {

    private final String fileToBeSignedName = "a.pdf";
    private final String certificateSerialNumber = "-1898837518887619158";
    private final String keystorePassword = "ATYTXWY";

    @Autowired
    StorageProperties storageProperties;
    StorageService storageService;
    MockedStatic<AuthUtil> authUtil;
    MockedStatic<HttpUtils> httpUtils;
    SigningService signingService;
    SignatureUtil util;
    PdfDocument pdfDocument;
    SigningSession signingSession;
    @Mock
    GeoIPLocationService locationService;
    @Mock
    SigningSessionRepository signingSessionRepository;
    @Mock
    EmailService emailService;
    @Mock
    SmsService smsService;
    @Mock
    KeystoreLoader keystoreLoader;
    @Mock
    HttpServletRequest httpServletRequest;
    @Mock
    CertificateGenerationService certificateGenerationService;
    @Mock
    SigningSessionMapper signingSessionMapper;

    @BeforeEach
    void setUp() throws GeneralSecurityException, IOException, GeoIp2Exception, MessagingException,
            OperatorCreationException, PKCSException {
        MockitoAnnotations.openMocks(this);

        // ARRANGE
        Path fileToBeSignedPath = Paths.get(storageProperties.getUploadDir() + "/" + fileToBeSignedName);
        String keystorePath = storageProperties.getUploadCertDir() + "/" + certificateSerialNumber + ".pfx";

        Map<String, Object> principalClaims = new HashMap<>();
        principalClaims.put("email", "vucic.kat@gmail.com");
        principalClaims.put("given_name", "Katarina");
        principalClaims.put("family_name", "Vucic");
        principalClaims.put("mobile", "+381693724133");
        principalClaims.put("sub", "d59d13ba-da98-47a5-b245-cd82698adfdd");

        UUID signingSessionId = UUID.randomUUID();
        signingSession = SigningSession.builder()
                .userId(UUID.fromString((String) principalClaims.get("sub")))
                .id(signingSessionId)
                .status(Status.PENDING)
                .build();

        Document document = Document.builder()
                .signingSession(signingSession)
                .filePath(fileToBeSignedPath.toAbsolutePath().toString())
                .fileName(fileToBeSignedPath.getFileName().toString())
                .addedAt(Instant.now().getEpochSecond())
                .build();

        signingSession.setDocument(document);

        authUtil = Mockito.mockStatic(AuthUtil.class);
        authUtil.when(AuthUtil::getPrincipalClaims).thenReturn(principalClaims);

        // Arrange Approve signing deps
        storageService = Mockito.spy(new StorageServiceImpl(storageProperties));
        signingService = Mockito.spy(new SigningService(storageService, storageProperties, locationService, keystoreLoader));
        SigningSessionServiceImpl signingSessionService = Mockito.spy(
                new SigningSessionServiceImpl(signingSessionRepository, storageService, emailService, smsService,
                        locationService, signingService, certificateGenerationService, signingSessionMapper));

        Long certRequestedAt = Instant.now().getEpochSecond();
        when(certificateGenerationService.generateUserCertificate(any(), any(), any()))
                .thenAnswer(i -> {
                    Certificate certificate = Certificate.builder()
                            .signingSession(signingSession)
                            .serialNumber(new BigInteger(certificateSerialNumber))
                            .requestedAt(certRequestedAt)
                            .issuedAt(Instant.now().getEpochSecond())
                            .build();
                    signingSession.setCertificate(certificate);
                    return keystorePassword;
                });
        when(signingSessionService.save(any(SigningSession.class))).thenAnswer(i -> i.getArguments()[0]);
        doReturn(signingSession).when(signingSessionService).findById(any(UUID.class));

        // Approve signing
        signingSessionService.approveSigningSession(signingSession.getId(), true, Instant.now().getEpochSecond());

        // Arrange Signing deps
        httpUtils = Mockito.mockStatic(HttpUtils.class);
        httpUtils.when(() -> HttpUtils.getRequestIPAddress(httpServletRequest)).thenReturn("109.245.194.170");

        when(locationService.getLocation(anyString())).thenReturn(
                new GeoIP("109.245.194.170", "Belgrade", "Serbia", "44", "22"));
        when(certificateGenerationService.verifyKeystorePassword(signingSession, keystorePassword)).thenReturn(true);
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(new FileInputStream(keystorePath), keystorePassword.toCharArray());
        doReturn(Paths.get(keystorePath)).when(storageService).loadCert(certificateSerialNumber + ".pfx");
        doNothing().when(storageService).deleteKeystore(certificateSerialNumber + ".pfx");
        doReturn(keyStore).when(keystoreLoader).loadKeystore(signingSession, keystorePassword);
        doReturn(fileToBeSignedPath).when(storageService).load(signingSession.getDocument().getFileName());

        // Sign document
        signingSessionService.sign(signingSession.getId(), keystorePassword, httpServletRequest);
    }

    @AfterEach
    void tearDown() {
        signingSession = null;
        storageService = null;
        signingService = null;
        authUtil.close();
        httpUtils.close();
        if (pdfDocument != null && !pdfDocument.isClosed()) {
            pdfDocument.close();
        }
        util = null;
    }

    @Test
    @DisplayName("Signing session fields updated during approval and signing")
    void sessionFieldsUpdated() {
        assertNotNull(signingSession.getCertificate(), "Certificate generated");
        assertTrue(signingSession.getConsent(), "Consent for signing is given");
        assertEquals(Status.SIGNED, signingSession.getStatus(), "Status is changed to SIGNED");
        assertTrue((signingSession.getCertificate().getIssuedAt() -
                        signingSession.getCertificate().getRequestedAt()) < 10,
                "Certificate is issued closely to the requested time");
    }

    @Test
    @DisplayName("Signed and approved document fields correspond")
    void testSignedDocumentFieldsAndApproved() throws GeneralSecurityException, IOException {
        // extract signature details
        Path signedDocumentPath = Paths.get(storageProperties.getDownloadDir() + "/" + signingSession.getId()
                + "_" + signingSession.getDocument().getFileName());
        pdfDocument = new PdfDocument(new PdfReader(signedDocumentPath.toString()));
        util = new SignatureUtil(pdfDocument);

        // test fields
        PdfSignature sig = util.getSignature("Advanced Electronic Signature");
        Security.addProvider(new BouncyCastleProvider());
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
        byte[] keyBytes = java.util.Base64.getDecoder().decode(signingSession.getCertificate().getCertificate());
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(keyBytes));
        String serial = cert.getSerialNumber().toString();

        assertNotNull(sig.getReason(), "Reason is not null");
        assertTrue(sig.getReason().contains(signingSession.getId().toString()),
                "Reason contains valid signing session ID");
        assertTrue(sig.getReason().contains(serial), "Reason contains certificate serial number");
        assertTrue(sig.getReason().contains(signingSession.getCertificate().getSerialNumber().toString()),
                "Reason contains certificate serial number from signing session");
    }
}