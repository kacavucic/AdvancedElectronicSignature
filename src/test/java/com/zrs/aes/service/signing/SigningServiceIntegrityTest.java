package com.zrs.aes.service.signing;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.when;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.signatures.PdfPKCS7;
import com.itextpdf.signatures.PdfSignature;
import com.itextpdf.signatures.SignatureUtil;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.zrs.aes.persistence.model.Certificate;
import com.zrs.aes.persistence.model.Document;
import com.zrs.aes.persistence.model.SigningSession;
import com.zrs.aes.persistence.model.Status;
import com.zrs.aes.service.certificate.KeyStorePasswordGenerator;
import com.zrs.aes.service.certificate.KeystoreLoader;
import com.zrs.aes.service.location.GeoIP;
import com.zrs.aes.service.location.GeoIPLocationService;
import com.zrs.aes.service.storage.StorageProperties;
import com.zrs.aes.service.storage.StorageService;
import com.zrs.aes.service.storage.StorageServiceImpl;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.x509.util.StreamParsingException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
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

@ExtendWith(SpringExtension.class)
@ContextConfiguration(initializers = ConfigDataApplicationContextInitializer.class)
@EnableConfigurationProperties(value = SigningProperties.class)
@ActiveProfiles("local")
class SigningServiceIntegrityTest {

  private final String givenName = "Katarina";
  private final String familyName = "Vucic";
  private final String signatureFieldName = "Advanced Electronic Signature";
  private final String certSubjectName = "CN=Katarina Vucic";
  private final Path fileToBeSignedPath = Paths.get(
      "src/main/resources/static/uploadedDocuments/a.pdf");
  private final String location = "Belgrade, Serbia";
  private final String contact = "kattylicious98@gmail.com";
  private final String clientIp = "192.168.0.55";
  private final String serial = "8786430201938387781";


  SigningProperties signingProperties;
  StorageProperties storageProperties;
  StorageService storageService;
  @Mock
  GeoIPLocationService locationService;

  @Mock
  KeystoreLoader keystoreLoader;
  @Mock
  KeyStorePasswordGenerator keyPassGen;
  SigningService signingService;
  SignatureUtil util;
  PdfDocument pdfDocument;

  @BeforeEach
  void setUp()
      throws GeneralSecurityException, IOException, GeoIp2Exception, OCSPException, StreamParsingException,
      OperatorException {
    MockitoAnnotations.openMocks(this);

    storageProperties = new StorageProperties();
    storageProperties.setUploadDir("src/main/resources/static/uploadedDocuments");
    storageProperties.setDownloadDir("src/main/resources/static/signedDocuments");
    storageProperties.setUploadCertDir("src/main/resources/static/uploadedCerts");
    storageProperties.setRootCertPath("src/main/resources/encryption");
    storageService = new StorageServiceImpl(storageProperties);

    when(locationService.getLocation(anyString()))
        .thenReturn(new GeoIP(clientIp, "Belgrade", "Serbia", "44", "22"));
    signingProperties = new SigningProperties();
    signingProperties.setKeyPass("katarina");
    signingProperties.setStorePass("katarina");

    signingService = new SigningService(storageService, locationService, keystoreLoader);
    Map<String, Object> principalClaims = new HashMap();
    principalClaims.put("email", contact);
    principalClaims.put("given_name", givenName);
    principalClaims.put("family_name", familyName);
    principalClaims.put("mobile", "123456789");
    principalClaims.put("name", givenName + " " + familyName);
    principalClaims.put("sub", "d59d13ba-da98-47a5-b245-cd82698adfdd");

    Certificate signingCert = new Certificate();
    signingCert.setId(UUID.randomUUID());
    signingCert.setIssuedAt(Instant.now().getEpochSecond());
    signingCert.setSerialNumber(new BigInteger(serial));
    signingCert.setRequestedAt(Long.MIN_VALUE);
    SigningSession signingSession = SigningSession.builder()
        .userId(UUID.fromString((String) principalClaims.get("sub")))
        .status(Status.IN_PROGRESS)
        .consent(true)
        .certificate(signingCert)
        .id(UUID.randomUUID())
        .build();
    signingCert.setSigningSession(signingSession);
    Document document = Document.builder()
        .signingSession(signingSession)
        .filePath(fileToBeSignedPath.toAbsolutePath().toString())
        .fileName(fileToBeSignedPath.getFileName().toString())
        .build();

    signingSession.setDocument(document);
    when(keyPassGen.generate())
        .thenReturn("RANDOMPASSWORD");
    // ACT
    Files.copy(Paths.get("src/main/resources/static/" + serial + ".pfx"),
        Paths.get("src/main/resources/static/uploadedCerts/" + serial + ".pfx"));

    // sign document
    Path outPdfPath = signingService.sign(signingSession, clientIp, principalClaims,
        "RANDOMPASSWORD");

    // extract signature details
    pdfDocument = new PdfDocument(new PdfReader(outPdfPath.toString()));
    util = new SignatureUtil(pdfDocument);
  }

  @AfterEach
  void tearDown() {
    signingService = null;
    util = null;

    // close file
    pdfDocument.close();
    pdfDocument = null;
  }

  @Test
  @DisplayName("Signature field existence")
  void signatureField() {
    // does signature field exist
    assertTrue(util.doesSignatureFieldExist(signatureFieldName), "Signature field exists");
  }

  @Test
  @DisplayName("Signature existence")
  void signature() {
    // does signature exist
    PdfPKCS7 signature = util.readSignatureData(signatureFieldName);
    assertNotNull(signature, "Signature exists");
  }

  @Test
  @DisplayName("Signature field values match")
  void fieldsMatch() {
    // test fields
    PdfSignature sig = util.getSignature(signatureFieldName);
    assertTrue(sig.getReason().contains(contact), "Reason in the signature contains email");
    assertTrue(sig.getReason().contains(serial), "Reason in the signature contains serial");
    assertEquals(sig.getLocation(), location, "Location in the signature is valid");

    // test certificate details
    String certSubject =
        util.readSignatureData(signatureFieldName).getSigningCertificate().getSubjectX500Principal()
            .getName();
    assertEquals(certSubject, certSubjectName, "Certificate subject matches");
  }

  @Test
  @DisplayName("Signature validity and data integrity")
  void signatureValidityAndDataIntegrity() throws GeneralSecurityException {
    // checks that signature is genuine and the document was not modified
    PdfPKCS7 signature = util.readSignatureData(signatureFieldName);
    boolean genuineAndWasNotModified = signature.verifySignatureIntegrityAndAuthenticity();
//        boolean completeDocumentIsSigned = util.signatureCoversWholeDocument(signatureFieldName);

    // TODO Condition 'signature != null' is always 'true'
    Assumptions.assumingThat(signature != null,
        () -> {
          assertTrue(genuineAndWasNotModified, "Signature integrity and authenticity is verified");
          // Signature no longer covers whole document because DSS and document timestamp are added after signing
//                    assertTrue(completeDocumentIsSigned, "Signature covers whole document");
        });
//        assertTrue(util.signatureCoversWholeDocument(signatureFieldName), "Signature covers whole document");
  }
}