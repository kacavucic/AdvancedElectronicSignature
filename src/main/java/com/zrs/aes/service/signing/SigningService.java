package com.zrs.aes.service.signing;

import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
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

    @Autowired
    public SigningService(SigningProperties signingProperties) {
        this.STORE_PASS = signingProperties.getStorePass().toCharArray();
        this.KEY_PASS = signingProperties.getKeyPass().toCharArray();
    }

    public Path sign(Path fileToBeSignedPath, String reason, String location, String contact)
            throws GeneralSecurityException, IOException {

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
        PdfSigner pdfSigner = new PdfSigner(pdfReader, result, new StampingProperties().preserveEncryption().useAppendMode());
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
}
