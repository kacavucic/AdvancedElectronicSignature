package com.zrs.aes.service.signing;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.*;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.zrs.aes.persistence.model.SigningSession;
import com.zrs.aes.service.location.GeoIP;
import com.zrs.aes.service.location.GeoIPLocationService;
import com.zrs.aes.service.location.HttpUtils;
import com.zrs.aes.service.storage.IStorageService;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.UUID;

@Service
public class SigningService {
    // TODO generate application-local.yml.aes again because of STORE_PASS and KEY_PASS

    final String BASE_DEST = "src/main/resources/static/signedDocuments/";
    final String STORE_PATH = "src/main/resources/encryption/keystore.jks";
    final char[] STORE_PASS;
    final char[] KEY_PASS;
    private IStorageService storageService;
    private GeoIPLocationService locationService;

    public SigningService(SigningProperties signingProperties, IStorageService storageService,
                          GeoIPLocationService locationService) {
        this.STORE_PASS = signingProperties.getStorePass().toCharArray();
        this.KEY_PASS = signingProperties.getKeyPass().toCharArray();
        this.storageService = storageService;
        this.locationService = locationService;
    }

    private static String getFileChecksum(MessageDigest digest, File file) throws IOException {
        //Get file input stream for reading the file content
        FileInputStream fis = new FileInputStream(file);

        //Create byte array to read data in chunks
        byte[] byteArray = new byte[1024];
        int bytesCount = 0;

        //Read file data and update in message digest
        while ((bytesCount = fis.read(byteArray)) != -1) {
            digest.update(byteArray, 0, bytesCount);
        }
        ;

        //close the stream; We don't need it now.
        fis.close();

        //Get the hash's bytes
        byte[] bytes = digest.digest();

        //This bytes[] has bytes in decimal format;
        //Convert it to hexadecimal format
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
        }

        //return complete hash
        return sb.toString();
    }

    public Path sign(SigningSession signingSession, HttpServletRequest request, Jwt principal)
            throws IOException, GeneralSecurityException, GeoIp2Exception {

        Path fileToBeSignedPath = storageService.load(signingSession.getDocument().getFileName());

        String reason = prepareReason(signingSession, principal);
        String location = prepareLocation(request);
        String contact = principal.getClaimAsString("email");

        ///////////////////////////////////////////////////
        File file = new File(BASE_DEST);
        file.mkdir();

        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.removeProvider(provider.getName());
        Security.addProvider(provider);

        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(STORE_PATH), STORE_PASS);

        Enumeration<String> aliases = ks.aliases();
        String alias = aliases.nextElement();

        PrivateKey pk = (PrivateKey) ks.getKey(alias, KEY_PASS);
        Certificate[] chain = ks.getCertificateChain(alias);
        X509Certificate signerCert = (X509Certificate) chain[0];
        ///////////////////////////////////////////////////

        Path finalDestPath =
                Paths.get(BASE_DEST + UUID.randomUUID() + "_" + fileToBeSignedPath.getFileName().toString());

        PdfReader pdfReader = new PdfReader(fileToBeSignedPath.toString());
        OutputStream result = new FileOutputStream(finalDestPath.toString());
        PdfSigner pdfSigner =
                new PdfSigner(pdfReader, result, new StampingProperties().preserveEncryption().useAppendMode());
        pdfSigner.setFieldName("Advanced Electronic Signature");
//        pdfSigner.setCertificationLevel(PdfSigner.CERTIFIED_NO_CHANGES_ALLOWED);

        PdfDocument pdfDocument = new PdfDocument(new PdfReader(fileToBeSignedPath.toString()));

        PdfSignatureAppearance appearance = pdfSigner.getSignatureAppearance();
        appearance.setPageRect(new Rectangle(293, 16, 303, 101));
        appearance.setPageNumber(pdfDocument.getNumberOfPages());
        appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.DESCRIPTION);
        appearance.setReason(reason);
        appearance.setLocation(location);
        appearance.setContact(contact); // ???
        appearance.setSignatureCreator(provider.getName());

        IExternalSignature signature = new PrivateKeySignature(pk, "SHA256", provider.getName());
        IExternalDigest externalDigest = new BouncyCastleDigest();
        pdfSigner.signDetached(externalDigest, signature, chain, null, null, null, 0, PdfSigner.CryptoStandard.CADES);

        return finalDestPath;
    }

    private String prepareLocation(HttpServletRequest request) throws IOException, GeoIp2Exception {
        GeoIP geoIP;
        String clientIp = HttpUtils.getRequestIPAddress(request);
        if (clientIp.equals("0:0:0:0:0:0:0:1") || clientIp.equals("127.0.0.1")) {
            geoIP = locationService.getLocation("87.116.160.153");
        }
        else {
            geoIP = locationService.getLocation(clientIp);
        }
        return geoIP.getCity() + ", " + geoIP.getCountry();
    }

    private String prepareReason(SigningSession signingSession, Jwt principal)
            throws IOException, NoSuchAlgorithmException {
        File fileToBeSigned = new File(signingSession.getDocument().getFilePath());
//        HashCode hash = Files.hash(fileToBeSigned, Hashing.md5());
        MessageDigest shaDigest = MessageDigest.getInstance("SHA-256");
        String shaChecksum = getFileChecksum(shaDigest, fileToBeSigned);

        return "On behalf of " + principal.getClaimAsString("given_name") + " " +
                principal.getClaimAsString("family_name") + ", " + principal.getClaimAsString("email") + "\n"
                + "Using OTP " + signingSession.getOneTimePassword().getOtp() + " and timestamp " +
                signingSession.getOneTimePassword().getTimestamp() + "\n"
                +
                "Hash value of document: " + shaChecksum;
    }
}
