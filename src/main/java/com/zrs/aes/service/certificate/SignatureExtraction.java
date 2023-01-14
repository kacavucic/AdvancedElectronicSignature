package com.zrs.aes.service.certificate;

import com.itextpdf.kernel.pdf.PdfDictionary;
import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.signatures.PdfPKCS7;
import com.itextpdf.signatures.PdfSignature;
import com.itextpdf.signatures.SignatureUtil;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.util.encoders.HexEncoder;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.Security;

public class SignatureExtraction {
    final static File RESULT_FOLDER = new File("src/main/resources/static");

    public static void main(String args[])
            throws IOException, NoSuchFieldException, IllegalAccessException, CMSException, OperatorCreationException,
            GeneralSecurityException {

        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.removeProvider(provider.getName());
        extractHashes();
    }


    static void extractHashes() throws NoSuchFieldException, SecurityException,
            GeneralSecurityException, IllegalArgumentException, IllegalAccessException, IOException {
        String pdfPath = "C:/Users/ACER/Desktop/DIPLOMSKI/slike/sig.pdf";
        PdfReader pdfReader = new PdfReader(pdfPath);
        PdfDocument pdfDocument = new PdfDocument(pdfReader);
        SignatureUtil util = new SignatureUtil(pdfDocument);

        System.out.printf("  %s\n", "Advanced Electronic Signature");
        PdfPKCS7 signature = util.readSignatureData("Advanced Electronic Signature");
        PdfDictionary sigDict = util.getSignatureDictionary("Advanced Electronic Signature");
        PdfSignature pdfSignature = util.getSignature("Advanced Electronic Signature");
        System.out.printf("    Digest algorithm: %s\n", signature.getHashAlgorithm());
        signature.verify();

        Field digestAttrField = PdfPKCS7.class.getDeclaredField("digestAttr");
        digestAttrField.setAccessible(true);
        byte[] digestAttr = (byte[]) digestAttrField.get(signature);
        byte[] pkcs7 = pdfSignature.getContents().getValueBytes();

        if (digestAttr != null) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            new HexEncoder().encode(digestAttr, 0, digestAttr.length, baos);
            byte[] digestAttrHex = baos.toByteArray();
            System.out.printf("    Hash: %s\n", new String(digestAttrHex));

            Files.write(
                    new File(RESULT_FOLDER,
                            String.format("signedpdf-%s%s.hash", "Advanced Electronic Signature", "-attr")).toPath(),
                    digestAttr);
            Files.write(new File(RESULT_FOLDER,
                            String.format("signedpdf-%s%s.hash", "Advanced Electronic Signature", "-attr") + ".hex").toPath(),
                    digestAttrHex);
        }
        else {
            System.out.printf("    Hash: N/A\n");
        }

        if (pkcs7 != null) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            new HexEncoder().encode(pkcs7, 0, pkcs7.length, baos);
            byte[] pkcs7Hex = baos.toByteArray();
            System.out.printf("    Hash: %s\n", new String(pkcs7Hex));

            Files.write(
                    new File(RESULT_FOLDER,
                            String.format("pkcs7-%s%s.hash", "Advanced Electronic Signature", "-attr")).toPath(),
                    digestAttr);
            Files.write(new File(RESULT_FOLDER,
                            String.format("pkcs7-%s%s.hash", "Advanced Electronic Signature", "-attr") + ".hex").toPath(),
                    pkcs7Hex);
        }
        else {
            System.out.printf("    Hash: N/A\n");
        }
    }
}
