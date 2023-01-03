package com.zrs.aes.service.certificate;

import com.zrs.aes.persistence.model.Certificate;
import com.zrs.aes.persistence.model.SigningSession;
import com.zrs.aes.service.email.IEmailService;
import com.zrs.aes.service.signing.SigningProperties;
import com.zrs.aes.service.storage.IStorageService;
import com.zrs.aes.web.customexceptions.CustomFileNotFoundException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.springframework.stereotype.Service;
import org.thymeleaf.util.StringUtils;

import java.io.FileInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;


@Service
public class CertificateGenerationService {

    private static final String BC_PROVIDER = "BC";
    private static final String KEY_ALGORITHM = "RSA";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    final String STORE_PASS;
    final char[] KEY_PASS;
    private IStorageService storageService;
    private IEmailService emailService;

    public CertificateGenerationService(SigningProperties signingProperties, IStorageService storageService,
                                        IEmailService emailService) {
        this.STORE_PASS = signingProperties.getStorePass();
        this.KEY_PASS = signingProperties.getKeyPass().toCharArray();
        this.storageService = storageService;
        this.emailService = emailService;
    }

    private void generateRootCertificate() throws Exception {
        // Add the BouncyCastle Provider
//        Security.addProvider(new BouncyCastleProvider());

        // Initialize a new KeyPair generator
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC_PROVIDER);
        keyPairGenerator.initialize(2048);

        // Setup start date to yesterday and end date for 1 year validity
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, -1);
        Date startDate = calendar.getTime();

        calendar.add(Calendar.YEAR, 1);
        Date endDate = calendar.getTime();

        // First step is to create a root certificate
        // First Generate a KeyPair,
        // then a random serial number
        // then generate a certificate using the KeyPair
        KeyPair rootKeyPair = keyPairGenerator.generateKeyPair();
        BigInteger rootSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));

        // Issued By and Issued To same for root certificate
        X500Name rootCertIssuer = new X500Name("CN=AES PKI Root CA");
        X500Name rootCertSubject = rootCertIssuer;
        JcaContentSignerBuilder signerBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM);
        signerBuilder.setProvider(BC_PROVIDER);
        PrivateKey privateKey = rootKeyPair.getPrivate();
        ContentSigner rootCertContentSigner = signerBuilder.build(privateKey);
        X509v3CertificateBuilder rootCertBuilder =
                new JcaX509v3CertificateBuilder(rootCertIssuer, rootSerialNum, startDate, endDate, rootCertSubject,
                        rootKeyPair.getPublic());

        // Add Extensions
        // A BasicConstraint to mark root certificate as CA certificate
        JcaX509ExtensionUtils rootCertExtUtils = new JcaX509ExtensionUtils();
        rootCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        rootCertBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                rootCertExtUtils.createSubjectKeyIdentifier(rootKeyPair.getPublic()));

        rootCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.cRLSign | KeyUsage.keyCertSign));


        // Create a cert holder and export to X509Certificate
        X509CertificateHolder rootCertHolder = rootCertBuilder.build(rootCertContentSigner);
        X509Certificate rootCert =
                new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(rootCertHolder);

        storageService.exportRootKeyPairToKeystoreFile(rootKeyPair, rootCert, "root-cert", "root-cert.pfx", "PKCS12",
                STORE_PASS);

    }


    public String generateCertificate(Map<String, Object> principalClaims, SigningSession signingSession,
                                      Long certRequestedAt)
            throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        Path rootCertPath = null;
        boolean fileFound = false;
        while (!fileFound) {
            try {
                rootCertPath = storageService.loadRootCert("root-cert.pfx");
                fileFound = true;
            } catch (CustomFileNotFoundException ex) {
                generateRootCertificate();
            }
        }

        KeyStore keyStore = KeyStore.getInstance("PKCS12", BC_PROVIDER);
        keyStore.load(new FileInputStream(String.valueOf(rootCertPath)), STORE_PASS.toCharArray());
        KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry("root-cert",
                new KeyStore.PasswordProtection(STORE_PASS.toCharArray()));
        PrivateKey rootPrivateKey = privateKeyEntry.getPrivateKey();

        X509Certificate rootCert = (X509Certificate) keyStore.getCertificate("root-cert");

        X500Name rootCertIssuer = new X500Name(rootCert.getIssuerX500Principal().getName());
        X500Name rootCertSubject = new X500Name(rootCert.getSubjectX500Principal().getName());


        Calendar calendar = Calendar.getInstance();
        Date startDate = new Date(); // current time
        calendar.setTime(startDate);
        calendar.add(Calendar.MINUTE, 60);
        Date endDate = calendar.getTime();


        // Initialize a new KeyPair generator
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC_PROVIDER);
        keyPairGenerator.initialize(2048);

        // Generate a new KeyPair and sign it using the Root Cert Private Key
        // by generating a CSR (Certificate Signing Request)
        X500Name issuedCertSubject = new X500Name("CN=" + principalClaims.get("name"));
        BigInteger issuedCertSerialNum = new BigInteger(Long.toString(new SecureRandom().nextLong()));
        KeyPair issuedCertKeyPair = keyPairGenerator.generateKeyPair();

        PKCS10CertificationRequestBuilder
                p10Builder = new JcaPKCS10CertificationRequestBuilder(issuedCertSubject, issuedCertKeyPair.getPublic());
        JcaContentSignerBuilder csrBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER);

        // Sign the new KeyPair with the root cert Private Key
        ContentSigner csrContentSigner = csrBuilder.build(rootPrivateKey);
        PKCS10CertificationRequest csr = p10Builder.build(csrContentSigner);

        // Use the Signed KeyPair and CSR to generate an issued Certificate
        // Here serial number is randomly generated. In general, CAs use
        // a sequence to generate Serial number and avoid collisions
        X509v3CertificateBuilder issuedCertBuilder =
                new X509v3CertificateBuilder(rootCertIssuer, issuedCertSerialNum, startDate, endDate, csr.getSubject(),
                        csr.getSubjectPublicKeyInfo());

        JcaX509ExtensionUtils issuedCertExtUtils = new JcaX509ExtensionUtils();

        // Add Extensions
        // Use BasicConstraints to say that this Cert is not a CA
        issuedCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

        // Add Issuer cert identifier as Extension
        issuedCertBuilder.addExtension(Extension.authorityKeyIdentifier, false,
                issuedCertExtUtils.createAuthorityKeyIdentifier(rootCert));
        issuedCertBuilder.addExtension(Extension.subjectKeyIdentifier, false,
                issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));

        // Add intended key usage extension if needed
//        issuedCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.keyEncipherment));
        issuedCertBuilder.addExtension(Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature));

        // Add DNS name is cert is to used for SSL
        issuedCertBuilder.addExtension(Extension.subjectAlternativeName, false, new DERSequence(new ASN1Encodable[]{
                new GeneralName(GeneralName.dNSName, "mydomain.local"),
                new GeneralName(GeneralName.iPAddress, "127.0.0.1")
        }));

        X509CertificateHolder issuedCertHolder = issuedCertBuilder.build(csrContentSigner);
        X509Certificate issuedCert =
                new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(issuedCertHolder);

        // Verify the issued cert signature against the root (issuer) cert
        issuedCert.verify(rootCert.getPublicKey(), BC_PROVIDER);

        Long issuedAt = Instant.now().getEpochSecond();

        String keystorePassword = StringUtils.randomAlphanumeric(7).toUpperCase();

        if (signingSession.getCertificate() == null) {
            Certificate certificate = Certificate.builder()
                    .signingSession(signingSession)
                    .serialNumber(issuedCertSerialNum)
                    .requestedAt(certRequestedAt)
                    .issuedAt(issuedAt)
                    .build();

            signingSession.setCertificate(certificate);
        }
        else {
            signingSession.getCertificate().setSerialNumber(issuedCertSerialNum);
            signingSession.getCertificate().setRequestedAt(certRequestedAt);
            signingSession.getCertificate().setIssuedAt(issuedAt);
        }


        storageService.exportKeyPairToKeystoreFile(issuedCertKeyPair, issuedCert, "issued-cert",
                issuedCertSerialNum + ".pfx",
                "PKCS12", keystorePassword);

        return keystorePassword;

    }

    // TODO dodaj 3 timestamp-a na signature appereance

    public boolean verifyKeystorePassword(SigningSession signingSession, String keystorePassword)
            throws KeyStoreException, CertificateException, NoSuchAlgorithmException {
        Path uploadedCert = storageService.loadCert(signingSession.getCertificate().getSerialNumber() + ".pfx");

        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        try {
            ks.load(Files.newInputStream(uploadedCert), keystorePassword.toCharArray());

        } catch (IOException ex) {
            if (ex.getCause() instanceof UnrecoverableKeyException) {
                return false;
            }
        }
        return true;
    }

}