package com.zrs.aes.service.signing;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.signatures.PdfSignature;
import com.itextpdf.signatures.SignatureUtil;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.zrs.aes.persistence.model.Certificate;
import com.zrs.aes.persistence.model.Document;
import com.zrs.aes.persistence.model.SigningSession;
import com.zrs.aes.persistence.model.Status;
import com.zrs.aes.persistence.repository.ISigningSessionRepository;
import com.zrs.aes.request.ApproveSigningSessionRequest;
import com.zrs.aes.service.certificate.CertificateGenerationService;
import com.zrs.aes.service.certificate.KeyStorePasswordGenerator;
import com.zrs.aes.service.email.IEmailService;
import com.zrs.aes.service.location.GeoIP;
import com.zrs.aes.service.location.GeoIPLocationService;
import com.zrs.aes.service.signingSession.SigningSessionServiceImpl;
import com.zrs.aes.service.sms.ISmsService;
import com.zrs.aes.service.storage.IStorageService;
import com.zrs.aes.service.storage.StorageProperties;
import com.zrs.aes.service.storage.StorageServiceImpl;
import java.io.ByteArrayInputStream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import javax.mail.MessagingException;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(initializers = ConfigDataApplicationContextInitializer.class)
@EnableConfigurationProperties(value = SigningProperties.class)
@ActiveProfiles("local")
public class IrrefutabilityTest {
    private final String givenName = "Katarina";
    private final String familyName = "Vucic";
    private final String signatureFieldName = "Advanced Electronic Signature";
    private final Path fileToBeSignedPath = Paths.get("src/main/resources/static/uploadedDocuments/a.pdf");
    // TODO Sredi hash i odakle se cita
    private final String contact = "kattylicious98@gmail.com";
    private final String clientIp = "192.168.0.55";

    SigningProperties signingProperties;
    StorageProperties storageProperties;
    IStorageService storageService;
    @Mock
    GeoIPLocationService locationService;
    @Mock
    ISigningSessionRepository signingSessionRepository;
    @Mock
    IEmailService emailService;
    @Mock
    ISmsService smsService;
    @Mock
    KeyStorePasswordGenerator keyPassGen;
    SigningService signingService;
    SignatureUtil util;
    PdfDocument pdfDocument;
    SigningSession signingSession;
    CertificateGenerationService certGenerationService;

    @BeforeEach
    void setUp() throws GeneralSecurityException, IOException, GeoIp2Exception, MessagingException, Exception {
        MockitoAnnotations.openMocks(this);

        // ARRANGE

        // Arrange globals
        storageProperties = new StorageProperties();
        storageProperties.setUploadDir("src/main/resources/static/uploadedDocuments");
        storageProperties.setDownloadDir("src/main/resources/static/signedDocuments");
        storageProperties.setUploadCertDir("src/main/resources/static/uploadedCerts");
        storageProperties.setRootCertPath("src/main/resources/encryption");
        storageService = new StorageServiceImpl(storageProperties);
        signingProperties = new SigningProperties();
        signingProperties.setKeyPass("katarina");
        signingProperties.setStorePass("katarina");
        signingService = new SigningService(signingProperties, storageService, locationService);
        Map<String, Object> principalClaims = new HashMap();
        principalClaims.put("email", contact);
        principalClaims.put("given_name", givenName);
        principalClaims.put("family_name", familyName);
        principalClaims.put("name", givenName + " " + familyName);
        principalClaims.put("mobile", "123456789");
        principalClaims.put("sub", "d59d13ba-da98-47a5-b245-cd82698adfdd");

        signingSession = SigningSession.builder()
                .userId(UUID.fromString((String) principalClaims.get("sub")))
                .status(Status.PENDING)
                .id(UUID.randomUUID())
                .build();

        Document document = Document.builder()
                .signingSession(signingSession)
                .filePath(fileToBeSignedPath.toAbsolutePath().toString())
                .fileName(fileToBeSignedPath.getFileName().toString())
                .addedAt(Instant.now().getEpochSecond())
                .build();

        signingSession.setDocument(document);

        // Arrange Approve signing deps
        certGenerationService = new CertificateGenerationService(signingProperties, storageService, keyPassGen);
        SigningSessionServiceImpl signingSessionService = new SigningSessionServiceImpl(signingSessionRepository,
                storageService, emailService, smsService, locationService, signingService, certGenerationService);

        when(signingSessionService.save(any(SigningSession.class))).thenAnswer(i -> i.getArguments()[0]);

        // Arrange Signing deps
        when(locationService.getLocation(anyString()))
                .thenReturn(new GeoIP(clientIp, "Belgrade", "Serbia", "44", "22"));
        when(keyPassGen.generate())
                .thenReturn("RANDOMPASSWORD");
        ApproveSigningSessionRequest approveSigningSessionRequest = new ApproveSigningSessionRequest();
        approveSigningSessionRequest.setConsent(true);
        approveSigningSessionRequest.setCertRequestedAt(Instant.now().getEpochSecond());

        // ACT

        // Approve signing
        signingSession = signingSessionService.approveSigningSession(signingSession, approveSigningSessionRequest, principalClaims);

        // Sign document
        Path outPdfPath = signingService.sign(signingSession, clientIp, principalClaims, "RANDOMPASSWORD");
        // extract signature details
        pdfDocument = new PdfDocument(new PdfReader(outPdfPath.toString()));
        util = new SignatureUtil(pdfDocument);
    }

    @AfterEach
    void tearDown() {
        // TODO Check this
        signingService = null;
        util = null;

        // close file
        pdfDocument.close();
        pdfDocument = null;
    }

    @Test
    @DisplayName("Signing session fields updated during approval")
    void sessionFieldsUpdated() {
        Certificate cert = signingSession.getCertificate();
        assertNotNull(cert, "Certificate object is created");
        assertTrue(signingSession.getConsent(), "Signing consent is given");
        assertEquals(Status.IN_PROGRESS, signingSession.getStatus(), "Status is changed to IN PROGRESS");
        assertTrue((cert.getIssuedAt() - cert.getRequestedAt()) < 10, "Certificate is issued closely to the requested time");
        assertNotNull(cert.getCertificate(), "Public Certificate is extracted and stored in a system");
    }

    @Test
    @DisplayName("Signed and approved document fields correspond")
    void testSignedDocumentFieldsAndApproved() throws CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException {
        // test fields
        PdfSignature sig = util.getSignature(signatureFieldName);
        Security.addProvider(new BouncyCastleProvider());
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
        byte[] keyBytes = java.util.Base64.getDecoder().decode(signingSession.getCertificate().getCertificate());
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(new ByteArrayInputStream(keyBytes));
        String serial = cert.getSerialNumber().toString();

        assertNotNull(sig.getReason(), "Reason is not null");
        assertTrue(sig.getReason().contains(serial), "Reason contains certificate serial number");
        assertTrue(sig.getReason().contains(signingSession.getCertificate().getSerialNumber().toString()), "Reason contains certificate serial number from signing session");
    }
}
