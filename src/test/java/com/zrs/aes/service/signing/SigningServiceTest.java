package com.zrs.aes.service.signing;

import com.itextpdf.forms.PdfAcroForm;
import com.itextpdf.io.source.RASInputStream;
import com.itextpdf.io.source.RandomAccessFileOrArray;
import com.itextpdf.io.source.RandomAccessSourceFactory;
import com.itextpdf.kernel.pdf.*;
import com.itextpdf.signatures.PdfPKCS7;
import com.itextpdf.signatures.PdfSignature;
import com.itextpdf.signatures.SignatureUtil;
import org.bouncycastle.util.encoders.HexEncoder;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.ConfigDataApplicationContextInitializer;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SpringExtension.class)
@ContextConfiguration(initializers = ConfigDataApplicationContextInitializer.class)
@EnableConfigurationProperties(value = SigningProperties.class)
@ActiveProfiles("local")
class SigningServiceTest {

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

    SigningService signingService;

    @Autowired
    SigningProperties signingProperties;

    SignatureUtil util;
    PdfDocument pdfDocument;

    @BeforeEach
    void setUp() throws GeneralSecurityException, IOException {
        signingService = new SigningService(signingProperties);

        // sign document
        Path outPdfPath = signingService.sign(fileToBeSignedPath, reason, location, contact);

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
                    assertTrue(genuineAndWasNotModified, "Signature is valid");
                    assertTrue(completeDocumentIsSigned, "Signature is valid");
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