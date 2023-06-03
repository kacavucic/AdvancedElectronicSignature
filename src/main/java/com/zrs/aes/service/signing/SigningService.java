package com.zrs.aes.service.signing;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.*;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.zrs.aes.persistence.model.SigningSession;
import com.zrs.aes.service.certificate.KeystoreLoader;
import com.zrs.aes.service.location.GeoIP;
import com.zrs.aes.service.location.GeoIPLocationService;
import com.zrs.aes.service.storage.StorageService;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.text.SimpleDateFormat;
import java.util.*;

@Service
@Slf4j
public class SigningService {

    // TODO generate application-local.yml.aes again
    private static final String BASE_DEST = "src/main/resources/static/signedDocuments/";
    private static final String ISSUED_CERT_ALIAS = "issued-cert";
    private static final String DIGEST_ALGORITHM = "SHA-256";
    private final StorageService storageService;
    private final GeoIPLocationService locationService;
    private final KeystoreLoader keystoreLoader;

    public SigningService(StorageService storageService, GeoIPLocationService locationService,
                          KeystoreLoader keystoreLoader) {
        this.storageService = storageService;
        this.locationService = locationService;
        this.keystoreLoader = keystoreLoader;
    }

    public Path sign(SigningSession signingSession, String clientIp,
                     Map<String, Object> principalClaims, String keystorePassword)
            throws GeneralSecurityException, IOException, GeoIp2Exception {
        Path documentToBeSignedPath = storageService.load(signingSession.getDocument().getFileName());

        String reason = prepareReason(signingSession, principalClaims);
        String location = prepareLocation(clientIp);
        String contact = (String) principalClaims.get("email");

        createDirectoryForSignedDocuments();
        BouncyCastleProvider provider = initializeSecurityProvider();

        KeyStore keyStore = keystoreLoader.loadKeystore(signingSession, keystorePassword);
        KeyStore.PrivateKeyEntry privateKeyEntry = getPrivateKeyEntry(keyStore, keystorePassword);

        PrivateKey privateKey = privateKeyEntry.getPrivateKey();
        Certificate[] certificateChain = privateKeyEntry.getCertificateChain();

        Path signedDocumentPath = Paths.get(
                BASE_DEST + signingSession.getId() + "_" + documentToBeSignedPath.getFileName().toString());

        try (PdfReader pdfReader = new PdfReader(documentToBeSignedPath.toString());
             OutputStream outputStream = new FileOutputStream(signedDocumentPath.toString());
             PdfDocument pdfDocument = new PdfDocument(pdfReader)) {

            PdfSigner pdfSigner = new PdfSigner(new PdfReader(documentToBeSignedPath.toString()), outputStream,
                    new StampingProperties().preserveEncryption().useAppendMode());
            pdfSigner.setFieldName("Advanced Electronic Signature");

            addSignatureAppearance(pdfSigner, pdfDocument, reason, location, contact, provider);

            IExternalDigest externalDigest = new BouncyCastleDigest();
            IExternalSignature signature = new PrivateKeySignature(privateKey, "SHA256",
                    provider.getName());
            ICrlClient crlClient = getCrlClient();
            List<ICrlClient> crlList = getCrlList(crlClient);
            ITSAClient tsaClient = new TSAClientBouncyCastle("https://freetsa.org/tsr", "", "", 8192,
                    DIGEST_ALGORITHM);

            pdfSigner.signDetached(externalDigest, signature, certificateChain, crlList, null, tsaClient,
                    0,
                    PdfSigner.CryptoStandard.CADES);

            signingSession.getDocument().setSignedAt(pdfSigner.getSignDate().getTimeInMillis());
            signingSession.getCertificate().setCertificate(Base64.getEncoder()
                    .encodeToString(keyStore.getCertificate(ISSUED_CERT_ALIAS).getEncoded()));

            // dispose certificate
            storageService.deleteKeystore(signingSession.getCertificate().getSerialNumber() + ".pfx");

            addLTA(signedDocumentPath, crlClient, signingSession, documentToBeSignedPath);

            return signedDocumentPath;
        }
    }

    private List<ICrlClient> getCrlList(ICrlClient crlClient)
            throws IOException, GeneralSecurityException {
        try (FileInputStream inputStream = new FileInputStream(
                "C:/Users/ACER/Desktop/AdvancedElectronicSignature/aes/src/main/resources/encryption/file.crl")) {
            List<ICrlClient> crlList = new ArrayList<>();
            crlList.add(crlClient);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509CRL crl = (X509CRL) cf.generateCRL(inputStream);
            log.info("CRL valid until: " + crl.getNextUpdate());
            // log.info("Certificate revoked: " + crl.isRevoked(certificateChain[0]));
            return crlList;
        }
    }

    private ICrlClient getCrlClient() throws IOException {
        try (FileInputStream inputStream = new FileInputStream(
                "C:/Users/ACER/Desktop/AdvancedElectronicSignature/aes/src/main/resources/encryption/file.crl");
             ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            byte[] buf = new byte[1024];
            while (inputStream.read(buf) != -1) {
                outputStream.write(buf);
            }
            return new CrlClientOffline(outputStream.toByteArray());
        }
    }

    private void addSignatureAppearance(PdfSigner pdfSigner, PdfDocument pdfDocument, String reason,
                                        String location, String contact, BouncyCastleProvider provider) {
        PdfSignatureAppearance appearance = pdfSigner.getSignatureAppearance();
        Rectangle pageSize = pdfSigner.getDocument().getDefaultPageSize();
        appearance.setPageRect(new Rectangle(pageSize.getLeft() + 36, pageSize.getBottom() + 36,
                200, 100));
        appearance.setPageNumber(pdfDocument.getNumberOfPages());
        appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.DESCRIPTION);
        appearance.setReasonCaption("");
        appearance.setReason(reason);
        appearance.setLocation(location);
        appearance.setContact(contact); // ???
        appearance.setSignatureCreator(provider.getName());
    }

    private KeyStore.PrivateKeyEntry getPrivateKeyEntry(KeyStore keyStore, String keystorePassword)
            throws GeneralSecurityException {
        return (KeyStore.PrivateKeyEntry) keyStore.getEntry(ISSUED_CERT_ALIAS,
                new KeyStore.PasswordProtection(keystorePassword.toCharArray()));
    }

    private void createDirectoryForSignedDocuments() {
        File file = new File(BASE_DEST);
        file.mkdir();
    }

    private BouncyCastleProvider initializeSecurityProvider() {
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.removeProvider(provider.getName());
        Security.addProvider(provider);
        return provider;
    }

    private void addLTA(Path finalDestPath, ICrlClient crlClient, SigningSession signingSession,
                        Path fileToBeSignedPath) throws IOException, GeneralSecurityException {

        Path ltPath = Paths.get(
                BASE_DEST + signingSession.getId() + "_lt_" + fileToBeSignedPath.getFileName().toString());
        Path ltaPath = Paths.get(
                BASE_DEST + signingSession.getId() + "_lta_" + fileToBeSignedPath.getFileName().toString());

        extendFromBTToBLT(ltPath, finalDestPath, crlClient);
        extendFromBLTToBLTA(ltPath, ltaPath);
        enableLTVForTimestampSignature(ltaPath, finalDestPath);

        storageService.deleteFile(ltPath);
        storageService.deleteFile(ltaPath);
    }

    private void enableLTVForTimestampSignature(Path ltaPath, Path finalDestPath)
            throws IOException, GeneralSecurityException {
        // Enable LTV for timestamp signature
        try (PdfReader pdfReader = new PdfReader(ltaPath.toString());
             PdfWriter pdfWriter = new PdfWriter(finalDestPath.toString());
             PdfDocument pdfDocument = new PdfDocument(pdfReader, pdfWriter,
                     new StampingProperties().useAppendMode())) {
            ICrlClient ltaCrlClient = new CrlClientOnline();
            LtvVerification ltaV = new LtvVerification(pdfDocument);
            ltaV.addVerification("Signature Validation Data Timestamp", null, ltaCrlClient,
                    LtvVerification.CertificateOption.WHOLE_CHAIN, LtvVerification.Level.CRL,
                    LtvVerification.CertificateInclusion.YES);
            ltaV.merge();
        }
    }

    private void extendFromBLTToBLTA(Path ltPath, Path ltaPath)
            throws IOException, GeneralSecurityException {
        // Extend from B-LT to B-LTA
        try (PdfReader pdfReader = new PdfReader(ltPath.toString());
             OutputStream outputStream = new FileOutputStream(ltaPath.toString())) {
            PdfSigner pdfSigner = new PdfSigner(pdfReader, outputStream,
                    new StampingProperties().useAppendMode());
            ITSAClient tsaClient = new TSAClientBouncyCastle("https://freetsa.org/tsr", "", "", 8192,
                    DIGEST_ALGORITHM);
            pdfSigner.timestamp(tsaClient, "Signature Validation Data Timestamp");
        }
    }

    private void extendFromBTToBLT(Path ltPath, Path finalDestPath, ICrlClient crlClient)
            throws IOException, GeneralSecurityException {
        // Extend from B-T to B-LT
        try (PdfReader pdfReader = new PdfReader(finalDestPath.toString());
             PdfWriter pdfWriter = new PdfWriter(ltPath.toString());
             PdfDocument pdfDocument = new PdfDocument(pdfReader, pdfWriter,
                     new StampingProperties().useAppendMode())) {
            LtvVerification ltvVerification = new LtvVerification(pdfDocument);
            ltvVerification.addVerification("Advanced Electronic Signature", null, crlClient,
                    LtvVerification.CertificateOption.WHOLE_CHAIN, LtvVerification.Level.CRL,
                    LtvVerification.CertificateInclusion.YES);
            ltvVerification.merge();
        }
    }

    private String prepareLocation(String clientIp) throws IOException, GeoIp2Exception {
        GeoIP geoIP = locationService.getLocation(
                clientIp.equals("0:0:0:0:0:0:0:1") || clientIp.equals("127.0.0.1") ? "87.116.160.153"
                        : clientIp);
        return geoIP.getCity() + ", " + geoIP.getCountry();
    }

    private String prepareReason(SigningSession signingSession, Map<String, Object> principalClaims) {
        SimpleDateFormat sdf = new SimpleDateFormat("dd.MM.yyyy. HH:mm");
        return "Email address: "
                + principalClaims.get("email")
                + "\n"
                + "Phone number: "
                + principalClaims.get("mobile")
                + "\n"
                + "Based on the signing session with ID:"
                + "\n"
                + signingSession.getId()
                + "\n"
                + "for which the user was issued a certificate with serial number: "
                + "\n"
                + signingSession.getCertificate().getSerialNumber()
                + "\n"
                + "Recorded activities:"
                + "\n"
                + sdf.format(new Date(signingSession.getCertificate().getRequestedAt() * 1000))
                + " - signature requested"
                + "\n"
                + sdf.format(new Date(signingSession.getCertificate().getIssuedAt() * 1000))
                + " - certificate issued";
    }
}
