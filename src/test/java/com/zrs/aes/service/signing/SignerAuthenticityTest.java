package com.zrs.aes.service.signing;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.when;

import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.zrs.aes.exception.customexceptions.InvalidStatusException;
import com.zrs.aes.mapper.SigningSessionMapper;
import com.zrs.aes.persistence.model.SigningSession;
import com.zrs.aes.persistence.repository.SigningSessionRepository;
import com.zrs.aes.request.ApproveSigningSessionRequest;
import com.zrs.aes.response.SigningSessionResponse;
import com.zrs.aes.service.certificate.CertificateGenerationService;
import com.zrs.aes.service.certificate.KeyStorePasswordGenerator;
import com.zrs.aes.service.certificate.KeystoreLoader;
import com.zrs.aes.service.email.EmailService;
import com.zrs.aes.service.location.GeoIP;
import com.zrs.aes.service.location.GeoIPLocationService;
import com.zrs.aes.service.signingsession.SigningSessionServiceImpl;
import com.zrs.aes.service.sms.SmsService;
import com.zrs.aes.service.storage.StorageProperties;
import com.zrs.aes.service.storage.StorageService;
import com.zrs.aes.service.storage.StorageServiceImpl;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;
import java.util.UUID;
import javax.mail.MessagingException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(initializers = ConfigDataApplicationContextInitializer.class)
@EnableConfigurationProperties(value = SigningProperties.class)
@ActiveProfiles("local")
class SignerAuthenticityTest {

  private final String givenName = "Katarina";
  private final String familyName = "Vucic";
  private final String contact = "kattylicious98@gmail.com";
  private final String clientIp = "192.168.0.55";

  SigningProperties signingProperties;
  StorageProperties storageProperties;
  StorageService storageService;
  @Mock
  GeoIPLocationService locationService;
  @Mock
  KeystoreLoader keystoreLoader;
  @Mock
  SigningSessionRepository signingSessionRepository;

  @Mock
  EmailService emailService;
  @Mock
  SmsService smsService;
  SigningService signingService;
  SigningSession signingSession;
  SigningSessionResponse signingSessionResponse;
  SigningSessionMapper signingSessionMapper;
  SigningSessionServiceImpl signingSessionService;
  Map<String, Object> principalClaims;
  CertificateGenerationService certGenerationService;
  @Mock
  KeyStorePasswordGenerator keyPassGen;

  @BeforeEach
  void setUp()
      throws GeneralSecurityException, IOException, GeoIp2Exception, MessagingException, Exception {
    MockitoAnnotations.openMocks(this);

    when(keyPassGen.generate())
        .thenReturn("RANDOMPASSWORD");
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
    signingService = new SigningService(storageService, locationService, keystoreLoader);
    principalClaims = new HashMap();
    principalClaims.put("email", contact);
    principalClaims.put("given_name", givenName);
    principalClaims.put("family_name", familyName);
    principalClaims.put("mobile", "123456789");
    principalClaims.put("name", givenName + " " + familyName);
    principalClaims.put("sub", "d59d13ba-da98-47a5-b245-cd82698adfdd");

    // Arrange Initiate session deps
    File initialFile = new File("src/main/resources/static/uploadedDocuments/a.pdf");
    InputStream targetStream = new FileInputStream(initialFile);
    MockMultipartFile file = new MockMultipartFile("a.pdf", getRandomString() + ".pdf",
        "application/pdf", targetStream);

    // Arrange Approve signing deps
    certGenerationService = new CertificateGenerationService(signingProperties, storageService,
        keyPassGen);
    signingSessionService = new SigningSessionServiceImpl(signingSessionRepository,
        storageService, emailService, smsService, locationService, signingService,
        certGenerationService, signingSessionMapper);

    when(signingSessionService.save(any(SigningSession.class))).thenAnswer(
        i -> i.getArguments()[0]);

    // Arrange Signing deps
    when(locationService.getLocation(anyString()))
        .thenReturn(new GeoIP(clientIp, "Belgrade", "Serbia", "44", "22"));

    ApproveSigningSessionRequest approveSigningSessionRequest = new ApproveSigningSessionRequest();
    approveSigningSessionRequest.setConsent(true);
    approveSigningSessionRequest.setCertRequestedAt(Instant.now().getEpochSecond());
    // ACT

    // Initiate session
    signingSessionResponse = signingSessionService.initiateSigningSession(file);
    signingSession.setId(UUID.randomUUID());

    // Approve signing
    signingSessionResponse = signingSessionService.approveSigningSession(signingSession.getId(),
        approveSigningSessionRequest.getConsent(),
        approveSigningSessionRequest.getCertRequestedAt());
  }

  @AfterEach
  void tearDown() throws IOException {
    // TODO Check this
    signingService = null;
    signingSessionService = null;
    signingSession = null;
  }

  @Test
  @DisplayName("Reject different principal than one initiated the session")
  void rejectDifferentPrincipal() throws IOException, GeneralSecurityException, GeoIp2Exception {
    Map<String, Object> principalClaimsForged = new HashMap();
    principalClaims.put("email", "something@el.se");
    principalClaims.put("given_name", "John");
    principalClaims.put("family_name", "Doe");
    principalClaims.put("sub", "a59d13ba-da98-47a5-b245-cd82698adfda");
    MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
    // Sign document
    Exception exception = assertThrows(InvalidStatusException.class, () -> {
      signingSessionService.sign(signingSession.getId(), "RANDOMPASSWORD", mockHttpServletRequest);
    });
    String expectedMessage = "Provided session does not belong to current user (caller)";
    String actualMessage = exception.getMessage();

    assertEquals(actualMessage, expectedMessage, expectedMessage);
  }

  @Test
  @DisplayName("Accept only the same principal as one initiated the session")
  void acceptValidPrincipal() throws IOException, GeneralSecurityException, GeoIp2Exception {
    MockHttpServletRequest mockHttpServletRequest = new MockHttpServletRequest();
    // Sign document
    assertDoesNotThrow(() ->
            signingSessionService.sign(signingSession.getId(), "RANDOMPASSWORD",
                mockHttpServletRequest),
        "Same principal as one initiated the session is accepted");
  }

  private String getRandomString() {
    int leftLimit = 97; // letter 'a'
    int rightLimit = 122; // letter 'z'
    int targetStringLength = 10;
    Random random = new Random();

    String generatedString = random.ints(leftLimit, rightLimit + 1)
        .limit(targetStringLength)
        .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
        .toString();
    return generatedString;
  }
}
