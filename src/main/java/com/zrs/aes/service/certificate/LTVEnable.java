package com.zrs.aes.service.certificate;

import com.itextpdf.kernel.pdf.PdfDocument;
import com.itextpdf.kernel.pdf.PdfReader;
import com.itextpdf.kernel.pdf.PdfWriter;
import com.itextpdf.kernel.pdf.StampingProperties;
import com.itextpdf.signatures.*;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.x509.util.StreamParsingException;

import java.io.*;
import java.security.GeneralSecurityException;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.List;

public class LTVEnable {

    public static void main(String[] args)
            throws IOException, GeneralSecurityException, OCSPException, StreamParsingException, OperatorException {

        Security.addProvider(new BouncyCastleProvider());

        FileInputStream is = new FileInputStream(
                "C:/Users/ACER/Desktop/AdvancedElectronicSignature/aes/src/main/resources/encryption/file.crl");
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        byte[] buf = new byte[1024];
        while (is.read(buf) != -1) {
            baos.write(buf);
        }
        ICrlClient crlClient = new CrlClientOffline(baos.toByteArray());
        List<ICrlClient> crlList = new ArrayList<ICrlClient>();
        crlList.add(crlClient);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509CRL crl = (X509CRL) cf.generateCRL(new FileInputStream(
                "C:/Users/ACER/Desktop/AdvancedElectronicSignature/aes/src/main/resources/encryption/file.crl"));
        System.out.println("CRL valid until: " + crl.getNextUpdate());
        is.close();

        PdfReader pdfReader = new PdfReader(
                "C:/Users/ACER/Desktop/AdvancedElectronicSignature/aes/src/main/resources/static/signedDocuments/3e722cef-13b3-46e4-b709-59e18790d5b1_b.pdf");
        PdfWriter pdfWriter = new PdfWriter("pomozboze.pdf");
        PdfDocument pdfDoc = new PdfDocument(pdfReader, pdfWriter, new StampingProperties().useAppendMode());
        LtvVerification v = new LtvVerification(pdfDoc);

        v.addVerification("Advanced Electronic Signature", null, crlClient,
                LtvVerification.CertificateOption.WHOLE_CHAIN,
                LtvVerification.Level.CRL, LtvVerification.CertificateInclusion.YES);
        v.merge();

        pdfDoc.close();

        // lta
        PdfReader ltaReader = new PdfReader(
                "pomozboze.pdf");
        OutputStream os = new FileOutputStream("lta.pdf");
        PdfSigner ps = new PdfSigner(ltaReader, os, new StampingProperties().useAppendMode());
        ITSAClient tsaClient = new TSAClientBouncyCastle("https://freetsa.org/tsr", "", "", 8192, "SHA-256");
        ps.timestamp(tsaClient, "Signature Validation Data Timestamp");

        // enable ltv for lta
        PdfReader r = new PdfReader("lta.pdf");
        PdfWriter w = new PdfWriter("TSltv.pdf");
        PdfDocument d = new PdfDocument(r, w, new StampingProperties().useAppendMode());

        ICrlClient ltvCrl = new CrlClientOnline();
        LtvVerification vltv = new LtvVerification(d);
        vltv.addVerification("Signature Validation Data Timestamp", null, ltvCrl,
                LtvVerification.CertificateOption.WHOLE_CHAIN,
                LtvVerification.Level.CRL, LtvVerification.CertificateInclusion.YES);
        vltv.merge();
        d.close();
    }
}
