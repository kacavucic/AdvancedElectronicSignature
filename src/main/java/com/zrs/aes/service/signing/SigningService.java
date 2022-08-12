package com.zrs.aes.service.signing;

import com.itextpdf.kernel.colors.DeviceRgb;
import com.itextpdf.kernel.geom.Rectangle;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.kernel.pdf.canvas.PdfCanvas;
import com.itextpdf.kernel.pdf.xobject.PdfFormXObject;
import com.itextpdf.signatures.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.util.UUID;

@Service
public class SigningService {

    final String BASE_DEST = "src/main/resources/static/signedDocuments/";
    final String KEYSTORE = "src/main/resources/encryption/keystore.jks";
    final char[] KEYSTORE_PASSWORD;

    @Autowired
    public SigningService(SigningProperties signingProperties) {
        this.KEYSTORE_PASSWORD = signingProperties.getKeystorePassword().toCharArray();
    }

//    private final String keystorePassword;
//
//    @Autowired
//    public SigningService(SigningProperties signingProperties) {
//        this.keystorePassword = signingProperties.getKeystorePassword();
//    }
//
//    final char[] KEYSTORE_PASSWORD = keystorePassword.toCharArray();

    public Path sign(Path fileToBeSignedPath, String reason, String location)
            throws GeneralSecurityException, IOException {

        ///////////////////////////////////////////////////
        File file = new File(BASE_DEST);
        file.mkdir();
        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(new FileInputStream(KEYSTORE), KEYSTORE_PASSWORD);
        String alias = ks.aliases().nextElement();
        PrivateKey pk = (PrivateKey) ks.getKey(alias, KEYSTORE_PASSWORD);
        Certificate[] chain = ks.getCertificateChain(alias);
        ///////////////////////////////////////////////////

        Path finalDestPath = Paths.get(BASE_DEST + UUID.randomUUID() + "_" + fileToBeSignedPath.getFileName().toString());

        PdfReader reader = new PdfReader(fileToBeSignedPath.toString());
        PdfSigner signer = new PdfSigner(reader, new FileOutputStream(finalDestPath.toString()), new StampingProperties());
        PdfDocument pdfDocument = new PdfDocument(new PdfReader(fileToBeSignedPath.toString()));

        PdfSignatureAppearance appearance = signer.getSignatureAppearance();
        appearance.setPageRect(new Rectangle(293, 16, 303, 101));
        appearance.setPageNumber(pdfDocument.getNumberOfPages());
        appearance.setRenderingMode(PdfSignatureAppearance.RenderingMode.DESCRIPTION);
        appearance.setReason(reason);
        appearance.setLocation(location);

        PdfFormXObject layer0 = appearance.getLayer0();
        Rectangle rectangle = layer0.getBBox().toRectangle();
        PdfCanvas canvas = new PdfCanvas(layer0, signer.getDocument());
        canvas.setStrokeColor(new DeviceRgb(225, 234, 247)).setLineWidth(2);
        for (int i = (int) (rectangle.getLeft() - rectangle.getHeight()); i < rectangle.getRight(); i += 5)
            canvas.moveTo(i, rectangle.getBottom()).lineTo(i + rectangle.getHeight(), rectangle.getTop());
        canvas.stroke();

        signer.setFieldName("Advanced Electronic Signature");


        PrivateKeySignature pks = new PrivateKeySignature(pk, DigestAlgorithms.SHA256, provider.getName());
        IExternalDigest digest = new BouncyCastleDigest();

        // Sign the document using the detached mode, CMS or CAdES equivalent.
        signer.signDetached(digest, pks, chain, null, null, null,
                0, PdfSigner.CryptoStandard.CMS);

        return finalDestPath;
    }
}
