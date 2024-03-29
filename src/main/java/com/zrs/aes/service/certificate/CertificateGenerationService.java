package com.zrs.aes.service.certificate;

import com.zrs.aes.exception.customexceptions.CustomFileNotFoundException;
import com.zrs.aes.persistence.model.Certificate;
import com.zrs.aes.persistence.model.SigningSession;
import com.zrs.aes.service.signing.SigningProperties;
import com.zrs.aes.service.storage.StorageService;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.springframework.stereotype.Service;


@Service
public class CertificateGenerationService {

  private static final String BC_PROVIDER = "BC";
  private static final String KEY_ALGORITHM = "RSA";
  private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
  private static final String ROOT_CERT_ALIAS = "root-cert";
  private static final String ROOT_CERT_FILE_NAME = "root-cert.pfx";
  private static final String KEYSTORE_STORE_TYPE = "PKCS12";
  final String storePass;
  final char[] keyPass;
  private final StorageService storageService;
  private final KeyStorePasswordGenerator keyPassGenerator;
  X500Name rootCertSubject;
  private PrivateKey rootPrivateKey;
  private X509Certificate rootCert;

  // TODO dodaj 3 timestamp-a na signature appereance

  public CertificateGenerationService(SigningProperties signingProperties,
      StorageService storageService, KeyStorePasswordGenerator keyPassGenerator) {
    this.storePass = signingProperties.getStorePass();
    this.keyPass = signingProperties.getKeyPass().toCharArray();
    this.storageService = storageService;
    this.keyPassGenerator = keyPassGenerator;
  }

  public static Date calculateDate(int hoursInFuture) {
    long secs = System.currentTimeMillis() / 1000;
    return new Date((secs + (hoursInFuture * 60 * 60)) * 1000);
  }

  private void generateRootCertificate()
      throws NoSuchAlgorithmException, NoSuchProviderException, IOException, OperatorCreationException, CertificateException, CRLException {

    // Initialize a new KeyPair generator and generate KeyPair
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC_PROVIDER);
    keyPairGenerator.initialize(2048);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();

    // Create subject
    X500Name subject = new X500Name("CN=AES PKI Root CA");

    // Create random serial number
    BigInteger serialNumber = new BigInteger(Long.toString(new SecureRandom().nextLong()));

    // Create validity period of 1 year
    Calendar calendar = Calendar.getInstance();
    Date startDate = new Date(); // current time
    calendar.setTime(startDate);
    calendar.add(Calendar.YEAR, 1);
    Date endDate = calendar.getTime();

    X509v3CertificateBuilder certBuilder =
        new JcaX509v3CertificateBuilder(subject, serialNumber, startDate, endDate, subject,
            keyPair.getPublic());

    // Add extensions
    JcaX509ExtensionUtils rootCertExtUtils = new JcaX509ExtensionUtils();

    // A BasicConstraint to mark root certificate as CA certificate
    certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));

    // Add identifier of root certificate subject as extension
    certBuilder.addExtension(Extension.subjectKeyIdentifier, false,
        rootCertExtUtils.createSubjectKeyIdentifier(keyPair.getPublic()));

    // Set intended key usage extension
    certBuilder.addExtension(Extension.keyUsage, false,
        new KeyUsage(KeyUsage.cRLSign | KeyUsage.keyCertSign));

    JcaContentSignerBuilder contentSignerBuilder = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM);
    contentSignerBuilder.setProvider(BC_PROVIDER);
    ContentSigner contentSigner = contentSignerBuilder.build(keyPair.getPrivate());

    // Create a cert holder and export to X509Certificate
    X509CertificateHolder certHolder = certBuilder.build(contentSigner);
    X509Certificate rootCertificate =
        new JcaX509CertificateConverter().setProvider(BC_PROVIDER).getCertificate(certHolder);

    createEmptyCRL(rootCertificate, keyPair.getPrivate());

    storageService.exportRootKeyPairToKeystoreFile(keyPair, rootCertificate, ROOT_CERT_ALIAS,
        ROOT_CERT_FILE_NAME, KEYSTORE_STORE_TYPE,
        storePass);

  }

  private X509CRL createEmptyCRL(X509Certificate rootCert, PrivateKey rootPrivateKey)
      throws NoSuchAlgorithmException, CertificateEncodingException, CRLException, IOException,
      OperatorCreationException {

    X509v2CRLBuilder crlBuilder = new JcaX509v2CRLBuilder(rootCert.getSubjectX500Principal(),
        calculateDate(0));
    crlBuilder.setNextUpdate(calculateDate(24 * 7));

    // add extensions to CRL
    JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
    crlBuilder.addExtension(Extension.authorityKeyIdentifier, false,
        extUtils.createAuthorityKeyIdentifier(rootCert));

    ContentSigner signer =
        new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER)
            .build(rootPrivateKey);
    JcaX509CRLConverter converter = new JcaX509CRLConverter().setProvider(BC_PROVIDER);
    X509CRL crl = converter.getCRL(crlBuilder.build(signer));

    FileWriter fileWriter = new FileWriter(
        "C:/Users/ACER/Desktop/AdvancedElectronicSignature/aes/src/main/resources/encryption/file.pem");
    try (JcaPEMWriter pemWriter = new JcaPEMWriter(fileWriter)) {
      pemWriter.writeObject(crl);
    }

    try (FileOutputStream fos = new FileOutputStream(
        "C:/Users/ACER/Desktop/AdvancedElectronicSignature/aes/src/main/resources/encryption/file.crl")) {
      fos.write(crl.getEncoded());
    } catch (Exception e) {
      // ...
    }

    // TODO finally fos.close() ??

    return crl;
  }

  public boolean verifyKeystorePassword(SigningSession signingSession, String keystorePassword)
      throws GeneralSecurityException {
    Path uploadedCert = storageService.loadCert(
        signingSession.getCertificate().getSerialNumber() + ".pfx");

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

  public String generateUserCertificate(Map<String, Object> principalClaims,
      SigningSession signingSession,
      Long certRequestedAt)
      throws IOException, GeneralSecurityException, OperatorCreationException, PKCSException {
    // Add the BouncyCastle Provider
    Security.addProvider(new BouncyCastleProvider());

    // Load root certificate or generate new if it doesn't exist
    Path rootCertPath = null;
    boolean fileFound = false;
    while (!fileFound) {
      try {
        rootCertPath = storageService.loadRootCert(ROOT_CERT_FILE_NAME);
        fileFound = true;
      } catch (CustomFileNotFoundException ex) {
        generateRootCertificate();
      }
    }

    loadRootCertificate(rootCertPath);
    KeyPair userCertificateKeyPair = generateUserKeyPair();
    PKCS10CertificationRequest csr =
        generateCSR(userCertificateKeyPair, String.valueOf(principalClaims.get("name")));
    verifyCSR(csr);
    X509Certificate userCertificate = signCSR(csr);
    verifyUserCertificate(userCertificate);

    // Update signing session
    Long issuedAt = Instant.now().getEpochSecond();
    String keystorePassword = keyPassGenerator.generate();

    if (signingSession.getCertificate() == null) {
      Certificate certificate = Certificate.builder()
          .signingSession(signingSession)
          .serialNumber(userCertificate.getSerialNumber())
          .requestedAt(certRequestedAt)
          .issuedAt(issuedAt)
          .build();

      signingSession.setCertificate(certificate);
    } else {
      signingSession.getCertificate().setSerialNumber(userCertificate.getSerialNumber());
      signingSession.getCertificate().setRequestedAt(certRequestedAt);
      signingSession.getCertificate().setIssuedAt(issuedAt);
    }

    return lockAndStoreCertificate(userCertificateKeyPair, userCertificate, keystorePassword);

  }

  private String lockAndStoreCertificate(KeyPair userCertificateKeyPair,
      X509Certificate userCertificate, String keystorePassword) {
    // Lock keystore with password and save it as .pfx file
    // String keystorePassword = StringUtils.randomAlphanumeric(7).toUpperCase();
    storageService.exportKeyPairToKeystoreFile(userCertificateKeyPair, userCertificate, rootCert,
        "issued-cert",
        userCertificate.getSerialNumber() + ".pfx",
        KEYSTORE_STORE_TYPE, keystorePassword);

    return keystorePassword;
  }

  // TODO put all exceptions into restexceptionhandler

  private void verifyUserCertificate(X509Certificate userCertificate)
      throws CertificateException, NoSuchAlgorithmException, SignatureException, InvalidKeyException,
      NoSuchProviderException {
    // Check the user certificate signature with root public key
    userCertificate.verify(rootCert.getPublicKey(), BC_PROVIDER);
  }

  private X509Certificate signCSR(PKCS10CertificationRequest csr)
      throws OperatorCreationException, CertificateException, NoSuchAlgorithmException, CertIOException {

    // Create serial number for user certificate
    BigInteger serialNumber = new BigInteger(Long.toString(new SecureRandom().nextLong()));

    // Create validity period of 60 minutes for user certificate
    Calendar calendar = Calendar.getInstance();
    Date startDate = new Date(); // current time
    calendar.setTime(startDate);
    calendar.add(Calendar.YEAR, 1);
    Date endDate = calendar.getTime();

    // TODO vrati na staro

    // Create user certificate builder
    X509v3CertificateBuilder userCertBuilder =
        new X509v3CertificateBuilder(rootCertSubject, serialNumber, startDate, endDate,
            csr.getSubject(),
            csr.getSubjectPublicKeyInfo());

    // Add extensions
    JcaX509ExtensionUtils issuedCertExtUtils = new JcaX509ExtensionUtils();

    // Use BasicConstraints to state that user certificate is not a CA
    userCertBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));

    // Add identifier of user certificate issuer (root certificate) as extension
    userCertBuilder.addExtension(Extension.authorityKeyIdentifier, false,
        issuedCertExtUtils.createAuthorityKeyIdentifier(rootCert));

    // Add identifier of user certificate subject as extension
    userCertBuilder.addExtension(Extension.subjectKeyIdentifier, false,
        issuedCertExtUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo()));

    // Set intended key usage extension to 'digital signature' since user certificate should only be used to sign documents
    userCertBuilder.addExtension(Extension.keyUsage, false,
        new KeyUsage(KeyUsage.digitalSignature));

    // Sign user certificate with root private key
    JcaContentSignerBuilder contentSignerBuilder =
        new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER);
    ContentSigner contentSigner = contentSignerBuilder.build(rootPrivateKey);
    X509CertificateHolder userCertHolder = userCertBuilder.build(contentSigner);
    return new JcaX509CertificateConverter().setProvider(BC_PROVIDER)
        .getCertificate(userCertHolder);
  }

  private void verifyCSR(PKCS10CertificationRequest csr)
      throws OperatorCreationException, PKCSException {
    // Check CSR signature with user's public key
    JcaContentVerifierProviderBuilder contentVerifierProviderBuilder = new JcaContentVerifierProviderBuilder();
    ContentVerifierProvider contentVerifierProvider =
        contentVerifierProviderBuilder.build(csr.getSubjectPublicKeyInfo());
    if (!csr.isSignatureValid(contentVerifierProvider)) {
      throw new IllegalStateException("Invalid Signature on CSR");
    }
  }

  private PKCS10CertificationRequest generateCSR(KeyPair userCertificateKeyPair, String userName)
      throws OperatorCreationException {
    // Create CSR (Certificate Signing Request) with user's public key and subject
    X500Name subject = new X500Name("CN=" + userName);
    PKCS10CertificationRequestBuilder
        builder = new JcaPKCS10CertificationRequestBuilder(subject,
        userCertificateKeyPair.getPublic());

    // Sign CSR with user's private key
    JcaContentSignerBuilder contentSignerBuilder =
        new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(BC_PROVIDER);
    ContentSigner contentSigner = contentSignerBuilder.build(userCertificateKeyPair.getPrivate());
    return builder.build(contentSigner);
  }

  private KeyPair generateUserKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
    // Initialize a new KeyPair generator and generating private and public key for user
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM, BC_PROVIDER);
    keyPairGenerator.initialize(2048);
    return keyPairGenerator.generateKeyPair();
  }

  private void loadRootCertificate(Path rootCertPath)
      throws KeyStoreException, NoSuchProviderException, IOException, UnrecoverableEntryException,
      NoSuchAlgorithmException, CertificateException {
    // Extract root certificate
    KeyStore keyStore = KeyStore.getInstance(KEYSTORE_STORE_TYPE, BC_PROVIDER);
    keyStore.load(new FileInputStream(String.valueOf(rootCertPath)), storePass.toCharArray());
    KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keyStore.getEntry(
        ROOT_CERT_ALIAS,
        new KeyStore.PasswordProtection(storePass.toCharArray()));
    rootPrivateKey = privateKeyEntry.getPrivateKey();
    rootCert = (X509Certificate) keyStore.getCertificate(ROOT_CERT_ALIAS);
    rootCertSubject = new X500Name(rootCert.getSubjectX500Principal().getName());
  }

}

// TODO log fajlovi

//A certificate signing request (CSR) is a document that an entity (such as a server or individual) generates and submits
//to a certificate authority (CA) in order to request a certificate. A CSR contains information about the entity, such as
//its distinguished name (DN) and public key, and is signed using the private key of the entity.

//The CSR is not signed with the CA's private key, but instead signed by the entity requesting the certificate using its
//own private key. The signature on the CSR serves as proof that the request for a certificate is legitimate and that the
//entity requesting the certificate is in possession of the private key that corresponds to the public key in the CSR.

//When a CA receives a CSR, it uses the public key in the CSR to verify the signature and ensure that the request is
//legitimate. If the signature is valid, the CA will create a certificate using the information in the CSR and sign it
//with its own private key. The resulting certificate can be verified by anyone using the public key of the CA, allowing
//them to trust the identity information contained in the certificate.