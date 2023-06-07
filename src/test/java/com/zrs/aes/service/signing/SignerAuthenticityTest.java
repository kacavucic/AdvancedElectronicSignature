package com.zrs.aes.service.signing;

import com.zrs.aes.exception.customexceptions.InvalidUserException;
import com.zrs.aes.mapper.SigningSessionMapper;
import com.zrs.aes.persistence.model.Certificate;
import com.zrs.aes.persistence.model.SigningSession;
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
import com.zrs.aes.util.GenericMessage;
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
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
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
class SignerAuthenticityTest {

    private final String fileToBeSignedName = "a.pdf";
    private final String certificateSerialNumber = "-1898837518887619158";
    private final String keystorePassword = "ATYTXWY";

    @Autowired
    StorageProperties storageProperties;
    StorageService storageService;
    MockedStatic<AuthUtil> authUtil;
    MockedStatic<HttpUtils> httpUtils;
    SigningService signingService;
    SigningSession signingSession;
    Map<String, Object> principalClaims;
    SigningSessionServiceImpl signingSessionService;
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
    void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);

        Path fileToBeSignedPath = Paths.get(storageProperties.getUploadDir() + "/" + fileToBeSignedName);
        String keystorePath = storageProperties.getUploadCertDir() + "/" + certificateSerialNumber + ".pfx";

        principalClaims = new HashMap<>();
        principalClaims.put("email", "vucic.kat@gmail.com");
        principalClaims.put("given_name", "Katarina");
        principalClaims.put("family_name", "Vucic");
        principalClaims.put("mobile", "+381693724133");
        principalClaims.put("sub", "d59d13ba-da98-47a5-b245-cd82698adfdd");

        authUtil = Mockito.mockStatic(AuthUtil.class);
        authUtil.when(AuthUtil::getPrincipalClaims).thenReturn(principalClaims);

        // Arrange Initiate session deps
        storageService = Mockito.spy(new StorageServiceImpl(storageProperties));
        signingService = Mockito.spy(new SigningService(storageService, storageProperties, locationService,
                keystoreLoader));
        signingSessionService = Mockito.spy(new SigningSessionServiceImpl(signingSessionRepository, storageService,
                emailService, smsService, locationService, signingService, certificateGenerationService,
                signingSessionMapper));

        File initialFile = new File(fileToBeSignedPath.toString());
        InputStream targetStream = new FileInputStream(initialFile);
        MockMultipartFile file = new MockMultipartFile(fileToBeSignedName, fileToBeSignedName,
                "application/pdf", targetStream);
        doAnswer(i -> {
            UUID signingSessionId = UUID.randomUUID();
            signingSession = (SigningSession) i.getArguments()[0];
            signingSession.setId(signingSessionId);
            return signingSession;
        }).when(signingSessionService).save(any(SigningSession.class));

        // Initiate session
        signingSessionService.initiateSigningSession(file);

        // Arrange Approve signing deps
        doReturn(signingSession).when(signingSessionService).findById(any(UUID.class));
        Long certRequestedAt = Instant.now().getEpochSecond();
        when(certificateGenerationService.generateUserCertificate(any(), any(), any())).thenAnswer(i -> {
            Certificate certificate = Certificate.builder()
                    .signingSession(signingSession)
                    .serialNumber(new BigInteger(certificateSerialNumber))
                    .requestedAt(certRequestedAt)
                    .issuedAt(Instant.now().getEpochSecond())
                    .build();
            signingSession.setCertificate(certificate);
            return keystorePassword;
        });

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
    }

    @AfterEach
    void tearDown() {
        signingSession = null;
        storageService = null;
        signingService = null;
        authUtil.close();
        httpUtils.close();
    }

    @Test
    @DisplayName("Reject different principal than one initiated the session")
    void rejectDifferentPrincipal() {
        Map<String, Object> principalClaimsForged = new HashMap<>();
        principalClaimsForged.put("email", "something@el.se");
        principalClaimsForged.put("given_name", "John");
        principalClaimsForged.put("family_name", "Doe");
        principalClaimsForged.put("sub", "a59d13ba-da98-47a5-b245-cd82698adfda");
        authUtil.when(AuthUtil::getPrincipalClaims).thenReturn(principalClaimsForged);

        // Sign document
        UUID signingSessionId = signingSession.getId();
        Exception exception = assertThrows(InvalidUserException.class, () -> signingSessionService
                .sign(signingSessionId, keystorePassword, httpServletRequest));
        String expectedMessage = GenericMessage.ERROR_MESSAGE_INVALID_USER;
        String actualMessage = exception.getMessage();
        assertEquals(actualMessage, expectedMessage, expectedMessage);
    }

    @Test
    @DisplayName("Accept only the same principal as one initiated the session")
    void acceptValidPrincipal() {
        // Sign document
        assertDoesNotThrow(() -> signingSessionService.sign(signingSession.getId(), keystorePassword, httpServletRequest),
                "Same principal as one initiated the session is accepted");
    }
}
