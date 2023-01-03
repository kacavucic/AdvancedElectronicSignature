//package com.zrs.aes.service.signing;
//
//import com.itextpdf.kernel.pdf.PdfDocument;
//import com.itextpdf.kernel.pdf.PdfReader;
//import com.itextpdf.signatures.PdfPKCS7;
//import com.itextpdf.signatures.PdfSignature;
//import com.itextpdf.signatures.SignatureUtil;
//import com.maxmind.geoip2.exception.GeoIp2Exception;
//import com.zrs.aes.persistence.model.Document;
//import com.zrs.aes.persistence.model.OneTimePassword;
//import com.zrs.aes.persistence.model.SigningSession;
//import com.zrs.aes.persistence.model.Status;
//import com.zrs.aes.service.location.GeoIP;
//import com.zrs.aes.service.location.GeoIPLocationService;
//import com.zrs.aes.service.storage.IStorageService;
//import dev.samstevens.totp.time.SystemTimeProvider;
//import org.junit.jupiter.api.*;
//import org.junit.jupiter.api.extension.ExtendWith;
//import org.mockito.Mock;
//import org.mockito.MockitoAnnotations;
//import org.springframework.boot.context.properties.EnableConfigurationProperties;
//import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
//import org.springframework.test.context.ActiveProfiles;
//import org.springframework.test.context.ContextConfiguration;
//import org.springframework.test.context.junit.jupiter.SpringExtension;
//
//import java.io.IOException;
//import java.lang.reflect.Field;
//import java.nio.file.Path;
//import java.nio.file.Paths;
//import java.security.GeneralSecurityException;
//import java.security.NoSuchAlgorithmException;
//import java.util.HashMap;
//import java.util.Map;
//import java.util.UUID;
//
//import static org.junit.jupiter.api.Assertions.*;
//
//import static org.mockito.Mockito.*;
//
//@ExtendWith(SpringExtension.class)
//@ContextConfiguration(initializers = ConfigDataApplicationContextInitializer.class)
//@EnableConfigurationProperties(value = SigningProperties.class)
//@ActiveProfiles("local")
//public class SigningServiceIntegrityTest {
//
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
//    private final String location = "Belgrade, Serbia";
//    private final String contact = "kattylicious98@gmail.com";
//    private final String clientIp = "192.168.0.55";
//
//    SigningProperties signingProperties;
//    @Mock
//    IStorageService storageService;
//    @Mock
//    GeoIPLocationService locationService;
//    SigningService signingService;
//    SignatureUtil util;
//    PdfDocument pdfDocument;
//
//    @BeforeEach
//    void setUp() throws GeneralSecurityException, IOException, GeoIp2Exception {
//        MockitoAnnotations.openMocks(this);
//
//        when(locationService.getLocation(anyString()))
//                .thenReturn(new GeoIP(clientIp, "Belgrade", "Serbia", "44", "22"));
//        when(storageService.load(anyString()))
//                .thenReturn(fileToBeSignedPath);
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
//        OneTimePassword oneTimePassword = OneTimePassword.builder()
//                .otp("123456")
//                .secret("samplesecret")
//                .id(UUID.fromString((String) principalClaims.get("sub")))
//                .timestamp(1668872875l)
//                .build();
//        SigningSession signingSession = SigningSession.builder()
//                .userId(UUID.fromString((String) principalClaims.get("sub")))
//                .status(Status.IN_PROGRESS)
//                .consent(true)
//                .oneTimePassword(oneTimePassword)
//                .build();
//        oneTimePassword.setSigningSession(signingSession);
//        Document document = Document.builder()
//                .signingSession(signingSession)
//                .filePath(fileToBeSignedPath.toAbsolutePath().toString())
//                .fileName(fileToBeSignedPath.getFileName().toString())
//                .addedOn(new SystemTimeProvider().getTime())
//                .build();
//
//        signingSession.setDocument(document);
//
//        // ACT
//
//        // sign document
//        Path outPdfPath = signingService.sign(signingSession, clientIp, principalClaims);
//
//        // extract signature details
//        pdfDocument = new PdfDocument(new PdfReader(outPdfPath.toString()));
//        util = new SignatureUtil(pdfDocument);
//    }
//
//    @AfterEach
//    void tearDown() {
//        signingService = null;
//        util = null;
//
//        // close file
//        pdfDocument.close();
//        pdfDocument = null;
//    }
//
//    @Test
//    @DisplayName("Signature field existence")
//    void signatureField() {
//        // does signature field exist
//        assertTrue(util.doesSignatureFieldExist(signatureFieldName), "Signature field exists");
//    }
//
//    @Test
//    @DisplayName("Signature existence")
//    void signature() {
//        // does signature exist
//        PdfPKCS7 signature = util.readSignatureData(signatureFieldName);
//        assertNotNull(signature, "Signature exists");
//    }
//
//    @Test
//    @DisplayName("Signature validity and data integrity")
//    void signatureValidityAndDataIntegrity() throws GeneralSecurityException {
//        // checks that signature is genuine and the document was not modified
//        PdfPKCS7 signature = util.readSignatureData(signatureFieldName);
//        boolean genuineAndWasNotModified = signature.verifySignatureIntegrityAndAuthenticity();
//        boolean completeDocumentIsSigned = util.signatureCoversWholeDocument(signatureFieldName);
//
//        // TODO Condition 'signature != null' is always 'true'
//        Assumptions.assumingThat(signature != null,
//                () -> {
//                    assertTrue(genuineAndWasNotModified, "Signature integrity and authenticity is verified");
//                    assertTrue(completeDocumentIsSigned, "Signature covers whole document");
//                });
//    }
//
//    @Test
//    @DisplayName("Signature data integrity - manual")
//    void signatureDataIntegrityManual()
//            throws NoSuchFieldException, IllegalAccessException, NoSuchAlgorithmException, IOException {
//        System.out.println(signatureFieldName);
//        PdfPKCS7 signature = util.readSignatureData(signatureFieldName);
//        System.out.println("    Digest algorithm: " + signature.getHashAlgorithm());
//        Field digestAttrField = PdfPKCS7.class.getDeclaredField("digestAttr");
//        digestAttrField.setAccessible(true);
//        byte[] digestAttr = (byte[]) digestAttrField.get(signature);
//        System.out.println(digestAttr);
//    }
//
//    @Test
//    @DisplayName("Signature field values match")
//    void fieldsMatch() {
//        // test fields
//        PdfSignature sig = util.getSignature(signatureFieldName);
//        assertEquals(sig.getReason(), reason, "Reason in the signature is valid");
//        assertEquals(sig.getLocation(), location, "Location in the signature is valid");
//
//        // test certificate details
//        String certSubject =
//                util.readSignatureData(signatureFieldName).getSigningCertificate().getSubjectX500Principal().getName();
//        assertEquals(certSubject, certSubjectName, "Certificate subject matches");
//    }
//}