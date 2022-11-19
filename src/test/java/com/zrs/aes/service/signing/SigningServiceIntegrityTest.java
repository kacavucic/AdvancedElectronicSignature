package com.zrs.aes.service.signing;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.signatures.PdfPKCS7;
import com.itextpdf.signatures.PdfSignature;
import com.itextpdf.signatures.SignatureUtil;
import com.zrs.aes.persistence.model.Document;
import com.zrs.aes.persistence.model.SigningSession;
import com.zrs.aes.persistence.model.Status;
import com.zrs.aes.service.location.GeoIPLocationService;
import com.zrs.aes.service.storage.IStorageService;
import dev.samstevens.totp.time.SystemTimeProvider;
import org.json.JSONException;
import org.json.JSONObject;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(initializers = ConfigDataApplicationContextInitializer.class)
@EnableConfigurationProperties(value = SigningProperties.class)
@ActiveProfiles("local")
class SigningServiceIntegrityTest {

    private final String signatureFieldName = "Advanced Electronic Signature";
    private final String certSubjectName =
            "CN=www.aes.com,OU=Zastita racunarskih sistema,O=Fakultet organizacionih nauka,L=Belgrade,ST=Serbia,C=RS";
    private final Path fileToBeSignedPath = Paths.get("src/main/resources/static/uploadedDocuments/a.pdf");
    private final String reason = """
            On behalf of Aleksandar Milutinovic, kattylicious98@gmail.com
            Using OTP 401084 and timestamp 1662005485
            Hash value of document: c92376579219dfdf9241c7eb35298388014906667757348a91540f1391d2b757""";
    private final String location = "Belgrade, Serbia";
    private final String contact = " kattylicious98@gmail.com";
    String token =
            "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJQVU5NRjVEVWlZQVNTWWdoRmVVYU8xN3Z1OHJUT1FNVWM0VmRGQXBaMVJVIn0.eyJleHAiOjE2Njg4NzY5NDQsImlhdCI6MTY2ODg1ODk0NCwiYXV0aF90aW1lIjoxNjY4ODU4OTM3LCJqdGkiOiJmNjljNzJhOC1kNGRlLTQzNDQtYmUzMy1hNDljYjY2MTQ3OGQiLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODMvYXV0aC9yZWFsbXMvYWVzIiwiYXVkIjoiYWNjb3VudCIsInN1YiI6ImM1ZTI1YjFhLWZjNmUtNDdiMy1hNzc1LTZjZjk3MjllYzNjYiIsInR5cCI6IkJlYXJlciIsImF6cCI6ImFlcy1hcHAiLCJzZXNzaW9uX3N0YXRlIjoiZDFjMjgxNjYtNzFjMC00MWVkLWFkMTMtZTAxM2YyNDU4M2E3IiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyJodHRwOi8vbG9jYWxob3N0OjgwODEiLCJodHRwczovL29hdXRoLnBzdG1uLmlvIiwiaHR0cDovL2xvY2FsaG9zdDozMDAwIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJ1c2VyIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJwcm9maWxlIGVtYWlsIiwic2lkIjoiZDFjMjgxNjYtNzFjMC00MWVkLWFkMTMtZTAxM2YyNDU4M2E3IiwiZW1haWxfdmVyaWZpZWQiOnRydWUsIm5hbWUiOiJLYXRhcmluYSBWdWNpYyIsInByZWZlcnJlZF91c2VybmFtZSI6InZ1Y2ljLmthdEBnbWFpbC5jb20iLCJnaXZlbl9uYW1lIjoiS2F0YXJpbmEiLCJmYW1pbHlfbmFtZSI6IlZ1Y2ljIiwiZW1haWwiOiJ2dWNpYy5rYXRAZ21haWwuY29tIn0.KTb9mYddtvvJ1DBVZEsDup8MQeIDqfy4J_IM4urolzUt3ex-eb2KCNjNjDxYrK7Rf1N96uk9rB4n_bqrEZr9JaCG1Hy9WJdpLU_iXnm7ZQ-nUI-zj6P6hRozndNn30VgXv9gRmMvxmbebgCHPIgdawzR_05J2CawshXuQlQD3sLLtL-4K4zAdYzUXIy5fHmrsxh_eKRN_zmtprW-F2jqZPDl5U15iTwDGvSK58JumxiNDO2DmHYogbEOD7gzEUXYg0GBsFR3M1at08Rrzm9EnL75p02jZjkwi_1lt3uQYNYm2aNS-7UsNLDvS4w5Poi9o6IeXRL4vYtmPYDvJGgZCw";
    SigningService signingService;

    SigningProperties signingProperties;
    IStorageService storageService;
    GeoIPLocationService locationService;

    SignatureUtil util;
    PdfDocument pdfDocument;

    @BeforeEach
    void setUp() throws GeneralSecurityException, IOException, JSONException {
        signingService = new SigningService(signingProperties, storageService, locationService);

        Jwt jwt = Jwt.Builder.withTokenValue(token)
                .header("alg", "none")
                .claim("sub", "user")
                .claim("scope", "read").build();


        JSONObject jwtPayload = new JSONObject();
        jwtPayload.put("email", contact);
        String token = new JWebToken(jwtPayload).toString();


        SigningSession signingSession = SigningSession.builder()
                .userId(UUID.fromString(principal.getClaimAsString("sub")))
                .status(Status.PENDING)
                .build();

        Document document = Document.builder()
                .signingSession(signingSession)
                .filePath(filePath.toAbsolutePath().toString())
                .fileName(fileName)
                .addedOn(new SystemTimeProvider().getTime())
                .build();

        signingSession.setDocument(document);

        // sign document
        Path outPdfPath = signingService.sign();

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
    @DisplayName("Signature validity and data integrity")
    void signatureValidityAndDataIntegrity() throws GeneralSecurityException {
        // checks that signature is genuine and the document was not modified
        PdfPKCS7 signature = util.readSignatureData(signatureFieldName);
        boolean genuineAndWasNotModified = signature.verifySignatureIntegrityAndAuthenticity();
        boolean completeDocumentIsSigned = util.signatureCoversWholeDocument(signatureFieldName);

        // TODO Condition 'signature != null' is always 'true'
        Assumptions.assumingThat(signature != null,
                () -> {
                    assertTrue(genuineAndWasNotModified, "Signature integrity and authenticity is verified");
                    assertTrue(completeDocumentIsSigned, "Signature covers whole document");
                });
    }

    @Test
    @DisplayName("Signature data integrity - manual")
    void signatureDataIntegrityManual()
            throws NoSuchFieldException, IllegalAccessException, NoSuchAlgorithmException, IOException {
        System.out.println(signatureFieldName);
        PdfPKCS7 signature = util.readSignatureData(signatureFieldName);
        System.out.println("    Digest algorithm: " + signature.getHashAlgorithm());
        Field digestAttrField = PdfPKCS7.class.getDeclaredField("digestAttr");
        digestAttrField.setAccessible(true);
        byte[] digestAttr = (byte[]) digestAttrField.get(signature);
        System.out.println(digestAttr);
    }

    @Test
    @DisplayName("Signature field values match")
    void fieldsMatch() {
        // test fields
        PdfSignature sig = util.getSignature(signatureFieldName);
        assertEquals(sig.getReason(), reason, "Reason in the signature is valid");
        assertEquals(sig.getLocation(), location, "Location in the signature is valid");

        // test certificate details
        String certSubject =
                util.readSignatureData(signatureFieldName).getSigningCertificate().getSubjectX500Principal().getName();
        assertEquals(certSubject, certSubjectName, "Certificate subject matches");
    }
}